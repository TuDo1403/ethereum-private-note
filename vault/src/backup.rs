//! `vault backup`: the offline half, step by step. It leaves two public files (the record and a recovery
//! sheet); sending the record to a chain is a separate, online step that never needs a secret.
//!
//! The backup is the 2-of-3 layout: passphrase (x = 1), second factor (x = 2), paper share (x = 3). The
//! second factor is a YubiKey (a hardware share, masked on chain) or a share kept in 1Password and
//! unlocked with Touch ID (a paper share that lives in the password manager, see onepassword.rs).
//!
//! 1Password needs its servers, so the offline backup never runs `op`: it shows share 2 on a temporary
//! paper, and `vault op-store` (`op_store` below) types it into 1Password later, on an online machine
//! that never sees the seed, the passphrase or the paper share.

use crate::onepassword;
use crate::prompt::*;
use epn_core::bip39::{entropy_to_words, new_passphrase, words_to_entropy};
use epn_core::record::{
    ARGON_M_KIB, ARGON_T, Kind, new_header, pad, seal, stretch_passphrase, unseal,
};
use epn_core::{fido, hex, os_random, record_id, seed_fingerprint};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const PASS_X: u8 = 1;
const KEY_X: u8 = onepassword::X; // the YubiKey and the 1Password share are alternatives at x = 2
const PAPER_X: u8 = 3;

/// The second factor: a YubiKey (its credential id) or 1Password (the account and vault share 2 goes into).
enum Second {
    YubiKey(String),
    OnePassword { account: String, vault: String },
}

impl Second {
    fn kinds(&self) -> [Kind; 3] {
        match self {
            Second::YubiKey(_) => [Kind::Passphrase, Kind::Hardware, Kind::Paper],
            Second::OnePassword { .. } => [Kind::Passphrase, Kind::Paper, Kind::Paper],
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Second::YubiKey(_) => "YubiKey (+ its PIN)",
            Second::OnePassword { .. } => "1Password item (Touch ID)",
        }
    }
}

/// Make the user prove the passphrase is written down, exactly: restore normalises Unicode (NFKD) but not
/// case or spaces.
fn confirm_passphrase(pass: &str) -> Result<(), String> {
    for _ in 0..TRIES {
        clear();
        println!(
            "Now type the passphrase from your paper (hidden). It must match exactly: lowercase, one space between words."
        );
        if *ask_hidden("passphrase: ")? == pass {
            return Ok(());
        }
        println!("That did not match.");
        show_words("Here it is again (write it down carefully):", pass);
        pause("Press Enter to try again.")?;
    }
    Err("passphrase not confirmed; nothing was saved".into())
}

/// All 24 words must be typed back from the paper and match: a quiz on a few words would let a
/// miswritten word through, and a paper share has no other check until the day it is needed.
fn confirm_paper_share(x: u8, words: &str) -> Result<(), String> {
    for _ in 0..TRIES {
        clear();
        println!("Now type share {x} back from your paper, all 24 words (hidden).");
        if *enter_paper_share(x)? == words {
            return Ok(());
        }
        println!("That is not the share shown: some word on the paper is wrong or out of order.");
        show_words(
            &format!("Share {x} again (correct the paper carefully):"),
            words,
        );
        pause("Press Enter to type it again.")?;
    }
    Err("paper share not confirmed".into())
}

/// The recovery sheet. `factor` is the line naming the second factor and `key_arg`/`stdin` complete the
/// scripted restore for it; nothing on the sheet is secret.
fn sheet(record: &[u8], second: &Second, op_ref: &str, fingerprint: &str) -> String {
    let (factor, key_arg, stdin) = match second {
        Second::YubiKey(cred) => (
            format!("credential:       {cred}   (YubiKey, share {KEY_X}, rpId localhost)"),
            format!(" --key {KEY_X}={cred}"),
            format!("pass <passphrase>        paper {PAPER_X} <24 words>"),
        ),
        Second::OnePassword { account, .. } => (
            format!(
                "{}   (1Password asks for Touch ID)",
                onepassword::sheet_line(onepassword::X, op_ref, account)
            ),
            String::new(),
            format!(
                "pass <passphrase>   paper {} <words from `op read --account {account} <reference>`>   paper {PAPER_X} <24 words>",
                onepassword::X
            ),
        ),
    };
    format!(
        "Recovery sheet. Nothing here is secret: keep several copies (paper, email, cloud).\n\n\
         record id:        {id}   (SHA-256 of the record, first 8 bytes; `publish` prints the same id)\n\
         record:           0x{record}\n\
         seed fingerprint: {fingerprint}   (a verify-only restore must show the same)\n\
         {factor}\n\n\
         Where the record is stored on chain (printed by `publish`):\n\
         chain id:         ________\n\
         address:          __________________________________________\n\n\
         read:     cast code <address> --rpc-url <rpc>   (the code is 00, then the record)\n\
         restore:  vault restore   (guided, hidden prompts; choose \"verify only\" for a test restore)\n\
         scripted: recover restore 0x{record}{key_arg}\n\
         \x20         then type the factor lines on stdin, Ctrl-D to end (never in the command line):\n\
         \x20           {stdin}\n\
         format:   SPEC.md (print it with this sheet)\n\n\
         Any two of: passphrase, {second_name}, paper share restore the seed.\n\
         Keep a copy of the record (or this sheet) with the chain id, address and record id in the\n\
         storage place of each factor too, so any two factors arrive with what they need.\n",
        id = record_id(record),
        record = hex(record),
        second_name = second.name(),
    )
}

/// Every file written after a secret was shown goes through here: synced to disk, so a crash right after
/// cannot lose it, and a failure says plainly that the papers already written belong to no backup.
fn save(path: &str, contents: &str) -> Result<(), String> {
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(path)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()
    };
    write().map_err(|e| {
        format!("cannot write {path}: {e}\nThe backup is NOT saved. Destroy the papers written in this run (the passphrase, and the paper share if it was shown) and start again.")
    })
}

/// The seed, typed twice. BIP39's checksum is only 4 bits for 12 words (8 for 24), so a typo that is
/// another list word ("wave" for "wage") passes it one time in 16 and would be backed up silently.
/// Both entries must give the same entropy.
fn enter_seed() -> Result<Zeroizing<Vec<u8>>, String> {
    for _ in 0..TRIES {
        let words = ask_hidden("Type your seed words (hidden, 12 to 24 words): ")?;
        let first = match words_to_entropy(words.trim()) {
            Ok(e) => Zeroizing::new(e),
            Err(e) => {
                println!("{e}");
                continue;
            }
        };
        let again = ask_hidden("Type them again, to catch a typo (hidden): ")?;
        match words_to_entropy(again.trim()).map(Zeroizing::new) {
            Ok(second) if *second == *first => {
                println!(
                    "Accepted: {} words, both entries match.",
                    words.split_whitespace().count()
                );
                println!(
                    "Seed fingerprint: {}  (note it: a verify-only restore must show the same)",
                    seed_fingerprint(&first)
                );
                return Ok(first);
            }
            _ => println!("The two entries are not the same seed. Start again, slowly."),
        }
    }
    Err("seed not accepted".into())
}

/// The output folder is made and test-written before any secret is typed or shown: a read-only or full
/// disk must stop the backup here, not after the papers exist.
fn output_dir() -> Result<String, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let dir = format!("backup-{stamp}");
    std::fs::create_dir(&dir).map_err(|e| format!("cannot create {dir}: {e}"))?;
    let probe = format!("{dir}/.write-test");
    std::fs::write(&probe, "test")
        .and_then(|_| std::fs::remove_file(&probe))
        .map_err(|e| format!("cannot write in {dir}: {e}"))?;
    Ok(dir)
}

type Shares = Zeroizing<Vec<(u8, [u8; 32])>>;

/// Seals the seed under the three factors and proves that every pair opens the record before anything is
/// saved. `prf` is the YubiKey secret when share 2 is a YubiKey. Returns the record and the paper shares
/// (x, share). Copies of the pads made along the way are wiped on a best-effort basis only (see main.rs).
fn build_record(
    entropy: &[u8],
    pass: &str,
    kinds: &[Kind],
    prf: Option<&[u8; 32]>,
) -> Result<(Vec<u8>, Shares), String> {
    let header = new_header(ARGON_M_KIB, ARGON_T, &os_random(16), 2, kinds)?;
    let argon = Zeroizing::new(working(
        "Stretching the passphrase (Argon2id, 1 GiB)",
        || stretch_passphrase(pass, &header),
    )?);
    let mut pads: Shares = Zeroizing::new(Vec::with_capacity(2)); // never reallocates: no unwiped copy
    pads.push((PASS_X, pad(&*argon, &header, PASS_X)));
    if let Some(prf) = prf {
        pads.push((KEY_X, pad(prf, &header, KEY_X)));
    }
    let (record, paper) = seal(&header, &pads, entropy, &mut os_random)?;
    let paper: Shares = Zeroizing::new(paper);
    // One factor per share (pad or paper share), three in all: every pair must open the record.
    let all: Shares = Zeroizing::new([pads.as_slice(), paper.as_slice()].concat());
    for (i, j) in [(0, 1), (0, 2), (1, 2)] {
        if *Zeroizing::new(unseal(&record, &[all[i], all[j]])?.0) != entropy {
            return Err("self-check failed: nothing was saved, do not use this backup".into());
        }
    }
    println!("Self-check passed: every pair of factors opens the record.");
    Ok((record, paper))
}

fn paper_words(paper: &Shares, x: u8) -> Zeroizing<String> {
    let share = paper
        .iter()
        .find(|s| s.0 == x)
        .expect("seal returns every paper share");
    Zeroizing::new(entropy_to_words(&share.1))
}

pub fn backup(device: Option<String>) -> Result<(), String> {
    let dir = output_dir()?;

    clear();
    println!(
        "2-of-3 seed backup: passphrase + YubiKey or 1Password + paper share (any two restore your seed).\n"
    );
    println!(
        "Steps: 1 second factor  2 seed  3 passphrase  4 build, check and save the public files  5 paper share  6 next steps\n"
    );
    println!("Before you start:");
    println!("  - go OFFLINE (turn off wifi and unplug ethernet) and close other apps");
    println!("  - have paper and a pen ready, and the YubiKey plugged in if you use one");
    println!("  - nobody should be able to see the screen\n");
    println!("The public files will be saved in ./{dir}/ (checked writable).");
    pause("Press Enter when you are offline and ready.")?;

    println!();
    step(1, 6, &format!("Second factor (share {KEY_X})"), false);
    let options = [
        "YubiKey: a hardware key, unlocked with its PIN and a touch",
        "1Password: a 1Password item, unlocked with Touch ID (stored later, online, with `vault op-store`)",
    ];
    let second = if choose("Which second factor?", &options)? == 0 {
        let id = ask(
            "Paste the credential id if this key already has one from `vault`, or press Enter to make a new one: ",
        )?;
        Second::YubiKey(if id.is_empty() {
            println!(
                "Making a credential: enter the YubiKey PIN, then touch the key when it blinks."
            );
            let new = fido::enroll(device.as_deref())?;
            println!("credential id: {new}\n(it is saved on the recovery sheet; it is not secret)");
            new
        } else {
            fido::check_cred_id(&id)?; // a typo is found now, not after the seed and the papers
            id
        })
    } else {
        // Both asked for explicitly: with several accounts signed in, a default would let `op` choose, and
        // a work account (whose admins can reach it, and which ends with the job) must never be chosen silently.
        println!(
            "Use a PERSONAL 1Password account, never a work one. `op account list` shows yours."
        );
        let account = ask(
            "1Password account for share 2 (sign-in address or email, e.g. my.1password.com): ",
        )?;
        onepassword::check_account(&account)?;
        let vault = ask(&format!(
            "Vault in that account (`op vault list --account {account}` lists them): "
        ))?;
        onepassword::check_name("vault name", &vault)?;
        println!(
            "Keep the passphrase and the paper share OUT of this 1Password account: one account would then"
        );
        println!("hold two factors, and one breach of it would be enough to restore the seed.");
        println!(
            "1Password needs the network, so this backup does not touch it: share 2 is shown as 24 words for a"
        );
        println!(
            "TEMPORARY paper, and `vault op-store` puts it into 1Password later, on your online machine."
        );
        Second::OnePassword { account, vault }
    };

    println!();
    step(2, 6, "Seed (typed hidden, twice)", true);
    let entropy = enter_seed()?;

    // Generated, shown once, then proven.
    let pass = Zeroizing::new(new_passphrase(12));
    clear();
    step(3, 6, "Passphrase (7 generated words)", true);
    println!("Write it on paper now, in lowercase, one space between words.");
    println!(
        "Keep it apart from the paper share and from the second factor. It is NOT a wallet seed.\n"
    );
    show_words("passphrase:", &pass);
    println!();
    pause("Press Enter once it is written down; the screen will be cleared.")?;
    confirm_passphrase(&pass)?;

    clear();
    step(4, 6, "Building, checking and saving the backup", false);
    let prf = match &second {
        Second::YubiKey(cred) => {
            println!("Enter the YubiKey PIN, then touch the key when it blinks.");
            Some(Zeroizing::new(fido::secret(cred, device.as_deref())?))
        }
        Second::OnePassword { .. } => None,
    };
    let (record, paper) = build_record(&entropy, &pass, &second.kinds(), prf.as_deref())?;

    // Saved now, before any share leaves this process: once papers exist, the record they belong to must
    // be on disk. The 1Password item's name is fixed by the record id, so the sheet can name it.
    let fingerprint = seed_fingerprint(&entropy);
    let title = format!("epn-share-{}-{}", onepassword::X, record_id(&record));
    let op_ref = match &second {
        Second::OnePassword { vault, .. } => onepassword::reference(vault, &title),
        Second::YubiKey(_) => String::new(),
    };
    save(
        &format!("{dir}/record.hex"),
        &format!("0x{}\n", hex(&record)),
    )?;
    save(
        &format!("{dir}/recovery-sheet.txt"),
        &sheet(&record, &second, &op_ref, &fingerprint),
    )?;
    println!("Saved two PUBLIC files in ./{dir}/ : record.hex and recovery-sheet.txt");

    let share_words = paper_words(&paper, PAPER_X);
    println!();
    step(5, 6, "Paper share (24 words)", true);
    println!("Write it on paper, in a different place from the passphrase.");
    println!(
        "These 24 words look like a wallet seed but are NOT one. Label the paper \"backup share {PAPER_X}, not a wallet\".\n"
    );
    show_words(
        &format!("paper share (this is share {PAPER_X}):"),
        &share_words,
    );
    println!();
    pause("Press Enter once it is written down; you will type all 24 words back.")?;
    confirm_paper_share(PAPER_X, &share_words).map_err(|e| {
        format!("{e}. This backup is NOT usable: delete ./{dir}/, destroy the passphrase and paper share papers, and start again.")
    })?;
    clear();

    if let Second::OnePassword { .. } = &second {
        let x = onepassword::X;
        let words = paper_words(&paper, x);
        step(
            5,
            6,
            &format!("Share {x} for 1Password (24 words, TEMPORARY paper)"),
            true,
        );
        println!(
            "Write it on its own paper, labelled \"share {x}, for 1Password, destroy after `vault op-store`\"."
        );
        println!(
            "Never keep it with the paper share or the passphrase: any two of the three restore the seed.\n"
        );
        show_words(
            &format!("share {x} for 1Password (TEMPORARY paper):"),
            &words,
        );
        println!();
        pause("Press Enter once it is written down; you will type all 24 words back.")?;
        confirm_paper_share(x, &words).map_err(|e| {
            format!("{e}. This backup is NOT usable: delete ./{dir}/, destroy all three papers, and start again.")
        })?;
        clear();
    }

    step(
        6,
        6,
        &format!(
            "Backup made. Seed fingerprint: {fingerprint}   record id: {}",
            record_id(&record)
        ),
        false,
    );
    println!();
    let mut next = vec![format!(
        "TEST your papers now, offline: run `vault restore`, pick \"Verify only\" and try each pair of\n     \
         factors in turn. Each must show fingerprint {fingerprint}. The seed is never shown."
    )];
    if let Second::OnePassword { .. } = &second {
        let x = onepassword::X;
        next[0].push_str(&format!("\n     For share {x}, answer no to reading it from 1Password and type the temporary paper."));
        next.push(format!(
            "on your online machine with 1Password (never this one), put share {x} into 1Password:\n       \
             vault op-store {dir}/recovery-sheet.txt\n     \
             then DESTROY the temporary share-{x} paper (shred or burn it)"
        ));
    }
    next.push(format!(
        "on an online machine, store the record on a chain (no secrets needed):\n       \
         publish <rpc-url> {dir}/record.hex <refund-address>\n     \
         it deploys the record as contract code from a throwaway key and prints chain id and address"
    ));
    next.push(
        "write chain id and address on the recovery sheet; keep several copies, and put a copy of the\n     \
         record (or the sheet) with these locators in the storage place of each factor paper too"
            .to_string(),
    );
    println!("Next:");
    for (i, item) in next.iter().enumerate() {
        println!("  {}. {item}", i + 1);
    }
    Ok(())
}

/// `vault op-store`: the online half of a 1Password backup. Share 2 is typed (twice) from the temporary
/// paper and stored in the item the recovery sheet names, then read back through the path a restore
/// uses. Only share 2 is ever on this machine, which is why it may be online.
pub fn op_store(sheet_path: &str) -> Result<(), String> {
    let x = onepassword::X;
    let text = std::fs::read_to_string(sheet_path)
        .map_err(|e| format!("cannot read {sheet_path}: {e}"))?;
    let r = onepassword::sheet_references(&text)
        .into_iter()
        .find(|r| r.x == x)
        .ok_or(
            "this recovery sheet names no 1Password share (was the backup made with a YubiKey?)",
        )?;
    let (vault, title) = onepassword::split_reference(&r.reference)?;
    clear();
    println!(
        "Store share {x} in 1Password: account {}, vault \"{vault}\", item \"{title}\".",
        r.account
    );
    println!(
        "Type it from the temporary paper. Only share {x} goes here: never the seed, the passphrase or share {PAPER_X}.\n"
    );
    let words = enter_paper_share(x)?;
    println!("\nAgain, to catch a word that is a valid word but the wrong one:");
    if *enter_paper_share(x)? != *words {
        return Err("the two entries differ: nothing was stored. Run this again, slowly.".into());
    }

    // A second run (say, after a failed read-back) must not make a duplicate: `op read` refuses a
    // reference that matches two items, which would break the restore.
    println!(
        "\nChecking that the item does not exist yet (1Password may ask for Touch ID; a message that it is not found is expected)."
    );
    match onepassword::read(&r.account, &r.reference) {
        Ok(existing) if *existing == *words => {
            println!(
                "Share {x} is already in 1Password as {} (checked). Now destroy the temporary share-{x} paper.",
                r.reference
            );
            return Ok(());
        }
        Ok(_) => {
            return Err(format!(
                "1Password already has an item \"{title}\" holding other words: nothing was stored. Check the paper before touching that item."
            ));
        }
        // A failed read does not prove the item is absent (1Password locked, Touch ID cancelled, offline).
        // A second item with the same title would make `op read` refuse the reference, so a person confirms.
        Err(e) => {
            println!("{e}");
            if !yes(&format!(
                "Does the 1Password app show NO item \"{title}\" in vault \"{vault}\"? (no stops here)"
            ))? {
                return Err("nothing was stored".into());
            }
        }
    }

    println!("Storing share {x}. 1Password may ask for Touch ID.");
    let reference = onepassword::store(&r.account, vault, title, &words)?;
    // Read back through the same path a restore uses: a wrong vault, a sync problem or a template
    // 1Password does not accept is caught now and not on the day the share is needed.
    let back = onepassword::read(&r.account, &reference).map_err(|e| {
        format!("{e}\nThe item \"{title}\" may now exist: check vault \"{vault}\" and delete it before running this again.")
    })?;
    if *back != *words {
        return Err(format!(
            "the item read back is not the share typed: delete the item \"{title}\" and run this again"
        ));
    }
    println!("Share {x} is in 1Password as {reference} (read back and checked).");
    println!(
        "Now destroy the temporary share-{x} paper (shred or burn it): with the paper share it would restore the seed."
    );
    Ok(())
}
