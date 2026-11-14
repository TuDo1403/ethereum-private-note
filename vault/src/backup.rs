//! `vault backup`: the offline half, step by step. It leaves two public files (the record and a recovery
//! sheet); sending the record to a chain is a separate, online step that never needs a secret.
//!
//! The backup is the 2-of-3 layout: passphrase (x = 1), second factor (x = 2), paper share (x = 3). The
//! second factor is a YubiKey (a hardware share, masked on chain) or a share kept in 1Password and
//! unlocked with Touch ID (a paper share that lives in the password manager, see onepassword.rs).

use crate::onepassword;
use crate::prompt::*;
use epn_core::bip39::{entropy_to_words, new_passphrase, words_to_entropy};
use epn_core::record::{ARGON_M_KIB, ARGON_T, Kind, new_header, pad, seal, stretch_passphrase, unseal};
use epn_core::{fido, hex, os_random, record_id, seed_fingerprint};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const PASS_X: u8 = 1;
pub const KEY_X: u8 = 2;
const PAPER_X: u8 = 3;

/// The second factor: a YubiKey (its credential id) or 1Password (the vault share 2 goes into).
enum Second {
    YubiKey(String),
    OnePassword(String),
}

impl Second {
    fn kinds(&self) -> [Kind; 3] {
        match self {
            Second::YubiKey(_) => [Kind::Passphrase, Kind::Hardware, Kind::Paper],
            Second::OnePassword(_) => [Kind::Passphrase, Kind::Paper, Kind::Paper],
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Second::YubiKey(_) => "YubiKey (+ its PIN)",
            Second::OnePassword(_) => "1Password item (Touch ID)",
        }
    }
}

/// Make the user prove the passphrase is written down, exactly: restore normalises Unicode (NFKD) but not
/// case or spaces.
fn confirm_passphrase(pass: &str) -> Result<(), String> {
    for _ in 0..TRIES {
        clear();
        println!("Now type the passphrase from your paper (hidden). It must match exactly: lowercase, one space between words.");
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
/// miswritten word through, and the paper share has no other check until the day it is needed.
fn confirm_paper_share(words: &str) -> Result<(), String> {
    for _ in 0..TRIES {
        clear();
        println!("Now type the paper share back from your paper, all 24 words (hidden).");
        if *enter_paper_share(PAPER_X)? == words {
            return Ok(());
        }
        println!("That is not the paper share shown: some word on the paper is wrong or out of order.");
        show_words("The paper share again (correct the paper carefully):", words);
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
        Second::OnePassword(_) => (
            format!("{:<18}share {} {op_ref}   (read with `op read`; 1Password asks for Touch ID)", onepassword::SHEET_PREFIX, onepassword::X),
            String::new(),
            format!("pass <passphrase>   paper {} <words from `op read`>   paper {PAPER_X} <24 words>", onepassword::X),
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
                println!("Accepted: {} words, both entries match.", words.split_whitespace().count());
                println!("Seed fingerprint: {}  (note it: a verify-only restore must show the same)", seed_fingerprint(&first));
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
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let dir = format!("backup-{stamp}");
    std::fs::create_dir(&dir).map_err(|e| format!("cannot create {dir}: {e}"))?;
    let probe = format!("{dir}/.write-test");
    std::fs::write(&probe, "test").and_then(|_| std::fs::remove_file(&probe)).map_err(|e| format!("cannot write in {dir}: {e}"))?;
    Ok(dir)
}

type Shares = Zeroizing<Vec<(u8, [u8; 32])>>;

/// Seals the seed under the three factors and proves that every pair opens the record before anything is
/// saved. `prf` is the YubiKey secret when share 2 is a YubiKey. Returns the record and the paper shares
/// (x, share). Copies of the pads made along the way are wiped on a best-effort basis only (see main.rs).
fn build_record(entropy: &[u8], pass: &str, kinds: &[Kind], prf: Option<&[u8; 32]>) -> Result<(Vec<u8>, Shares), String> {
    let header = new_header(ARGON_M_KIB, ARGON_T, &os_random(16), 2, kinds)?;
    println!("Stretching the passphrase (Argon2id, 1 GiB; takes a while)...");
    let argon = Zeroizing::new(stretch_passphrase(pass, &header)?);
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
        if unseal(&record, &[all[i], all[j]])?.0 != entropy {
            return Err("self-check failed: nothing was saved, do not use this backup".into());
        }
    }
    println!("Self-check passed: every pair of factors opens the record.");
    Ok((record, paper))
}

fn paper_words(paper: &Shares, x: u8) -> Zeroizing<String> {
    let share = paper.iter().find(|s| s.0 == x).expect("seal returns every paper share");
    Zeroizing::new(entropy_to_words(&share.1))
}

pub fn backup(device: Option<String>) -> Result<(), String> {
    let dir = output_dir()?;

    clear();
    println!("2-of-3 seed backup: passphrase + YubiKey or 1Password + paper share (any two restore your seed).\n");
    println!("Steps: 1 second factor  2 seed  3 passphrase  4 build, check and save the public files  5 paper share  6 next steps\n");
    println!("Before you start:");
    println!("  - go OFFLINE (turn off wifi and unplug ethernet) and close other apps");
    println!("  - have paper and a pen ready, and the YubiKey plugged in if you use one");
    println!("  - nobody should be able to see the screen\n");
    println!("The public files will be saved in ./{dir}/ (checked writable).");
    pause("Press Enter when you are offline and ready.")?;

    println!("\n1/6 Second factor (share {KEY_X})");
    println!("  1. YubiKey: a hardware key, unlocked with its PIN and a touch");
    println!("  2. 1Password: a share kept as a 1Password item, unlocked with Touch ID");
    println!("     (needs the 1Password app with \"Integrate with 1Password CLI\" on, and the `op` command)");
    let second = if choose_1_or_2()? == 1 {
        let id = ask("Paste the credential id if this key already has one from `vault`, or press Enter to make a new one: ")?;
        Second::YubiKey(if id.is_empty() {
            println!("Making a credential: enter the YubiKey PIN, then touch the key when it blinks.");
            let new = fido::enroll(device.as_deref())?;
            println!("credential id: {new}\n(it is saved on the recovery sheet; it is not secret)");
            new
        } else {
            id
        })
    } else {
        let v = ask("1Password vault to keep share 2 in (Enter for \"Private\"): ")?;
        let vault = if v.is_empty() { "Private".to_string() } else { v };
        onepassword::check_name("vault name", &vault)?;
        println!("Keep the passphrase and the paper share OUT of this 1Password account: one account would then");
        println!("hold two factors, and one breach of it would be enough to restore the seed.");
        Second::OnePassword(vault)
    };

    println!("\n2/6 Seed");
    let entropy = enter_seed()?;

    // Generated, shown once, then proven.
    let pass = Zeroizing::new(new_passphrase(7));
    clear();
    println!("3/6 Passphrase (7 generated words). Write it on paper now, in lowercase, one space between words.");
    println!("Keep it apart from the paper share and from the second factor. It is NOT a wallet seed.\n");
    show_words("passphrase:", &pass);
    println!();
    pause("Press Enter once it is written down; the screen will be cleared.")?;
    confirm_passphrase(&pass)?;

    clear();
    println!("4/6 Building the backup.");
    let prf = match &second {
        Second::YubiKey(cred) => {
            println!("Enter the YubiKey PIN, then touch the key when it blinks.");
            Some(Zeroizing::new(fido::secret(cred, device.as_deref())?))
        }
        Second::OnePassword(_) => None,
    };
    let (record, paper) = build_record(&entropy, &pass, &second.kinds(), prf.as_deref())?;

    // Saved now, before any share leaves this process: once papers or items exist, the record they belong
    // to must be on disk. The 1Password item's name is fixed by the record id, so the sheet can name it.
    let fingerprint = seed_fingerprint(&entropy);
    let title = format!("epn-share-{}-{}", onepassword::X, record_id(&record));
    let op_ref = match &second {
        Second::OnePassword(vault) => onepassword::reference(vault, &title),
        Second::YubiKey(_) => String::new(),
    };
    save(&format!("{dir}/record.hex"), &format!("0x{}\n", hex(&record)))?;
    save(&format!("{dir}/recovery-sheet.txt"), &sheet(&record, &second, &op_ref, &fingerprint))?;
    println!("Saved two PUBLIC files in ./{dir}/ : record.hex and recovery-sheet.txt");

    if let Second::OnePassword(vault) = &second {
        let words = paper_words(&paper, onepassword::X);
        println!("\nStoring share {} in 1Password (vault \"{vault}\"). 1Password may ask for Touch ID.", onepassword::X);
        // Read back through the same path a restore uses, so a wrong vault, a sync problem or a template
        // 1Password does not accept is caught now and not on the day the share is needed.
        let stored = onepassword::store(vault, &title, &words).and_then(|r| {
            let back = onepassword::read(&r)?;
            if *back == *words { Ok(r) } else { Err("the item read back from 1Password is not the share stored".into()) }
        });
        let reference = stored.map_err(|e| {
            format!("{e}\nThis backup is NOT usable: delete ./{dir}/ and the 1Password item \"{title}\" if it was made, destroy the passphrase paper, and start again.")
        })?;
        println!("Share {} is in 1Password as {reference} (read back and checked).", onepassword::X);
    }

    let share_words = paper_words(&paper, PAPER_X);
    println!("\n5/6 Paper share (24 words). Write it on paper, in a different place from the passphrase.");
    println!("These 24 words look like a wallet seed but are NOT one. Label the paper \"backup share {PAPER_X}, not a wallet\".\n");
    show_words(&format!("paper share (this is share {PAPER_X}):"), &share_words);
    println!();
    pause("Press Enter once it is written down; you will type all 24 words back.")?;
    confirm_paper_share(&share_words).map_err(|e| {
        format!("{e}. This backup is NOT usable: delete ./{dir}/, destroy the passphrase and paper share papers, and start again.")
    })?;
    clear();

    println!("6/6 Backup made. Seed fingerprint: {fingerprint}   record id: {}\n", record_id(&record));
    println!("Next:");
    println!("  1. TEST your papers now, offline: run `vault restore`, choose 2 (verify only) and try each pair of");
    println!("     factors in turn. Each must show fingerprint {fingerprint}. The seed is never shown.");
    println!("  2. on an online machine, store the record on a chain (no secrets needed):");
    println!("       publish <rpc-url> {dir}/record.hex <refund-address>");
    println!("     it deploys the record as contract code from a throwaway key and prints chain id and address");
    println!("  3. write chain id and address on the recovery sheet; keep several copies, and put a copy of the");
    println!("     record (or the sheet) with these locators in the storage place of each factor paper too");
    Ok(())
}
