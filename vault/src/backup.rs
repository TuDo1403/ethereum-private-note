//! `vault backup`: the offline half, step by step. It leaves two public files (the record and a recovery
//! sheet); sending the record to a chain is a separate, online step that never needs a secret.
//!
//! The setup is any the format allows (layout.rs): read from a plan file made by `vault plan`, or chosen
//! inline with the same screens. Shares are numbered passphrase, YubiKeys, then paper and 1Password shares.
//! A YubiKey share is a hardware share (masked on chain); a 1Password share is a paper share that lives in
//! the password manager and is unlocked with Touch ID (see onepassword.rs).
//!
//! 1Password needs its servers, so the offline backup never runs `op`: it shows each 1Password share on a
//! temporary paper, and `vault op-store` (`op_store` below) types it into 1Password later, on an online
//! machine that never sees the seed or any other share.

use crate::layout::{Layout, ShareKind};
use crate::onepassword;
use crate::prompt::*;
use crate::score::combinations;
use crate::setup;
use crate::sheet::{self, Locator};
use epn_core::bip39::{entropy_to_words, new_passphrase, words_to_entropy};
use epn_core::record::{ARGON_M_KIB, ARGON_T, new_header, pad, seal, stretch_passphrase, unseal};
use epn_core::{fido, hex, os_random, record_id, seed_fingerprint};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

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

/// Every file written after a secret was shown goes through here: synced to disk, so a crash right after
/// cannot lose it, and a failure says plainly that the papers already written belong to no backup.
fn save(path: &str, contents: &str) -> Result<(), String> {
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(path)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()
    };
    write().map_err(|e| {
        format!("cannot write {path}: {e}\nThe backup is NOT saved. Destroy the papers written in this run (the passphrase, and any share already shown) and start again.")
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

/// Seals the seed under the layout's shares and proves that every combination of k opens the record and
/// gives the seed, before anything is saved. `pass` is the passphrase when the layout has one (share 1) and
/// `prfs` the (x, secret) of each YubiKey share. Returns the record and the paper shares (x, share). Copies
/// of the pads made along the way are wiped on a best-effort basis only (see main.rs).
fn build_record(
    entropy: &[u8],
    pass: Option<&str>,
    layout: &Layout,
    prfs: &[(u8, [u8; 32])],
) -> Result<(Vec<u8>, Shares), String> {
    let (n, k) = (layout.n(), layout.k);
    let header = new_header(
        ARGON_M_KIB,
        ARGON_T,
        &os_random(16),
        k,
        &layout.record_kinds(),
    )?;
    // Every share fits: never reallocates, so no unwiped copy of a pad is left behind by a move.
    let mut pads: Shares = Zeroizing::new(Vec::with_capacity(n));
    if let Some(pass) = pass {
        // The fixed share order puts the passphrase first.
        debug_assert_eq!(layout.shares[0].kind, ShareKind::Passphrase);
        let argon = Zeroizing::new(working(
            "Stretching the passphrase (Argon2id, 1 GiB)",
            || stretch_passphrase(pass, &header),
        )?);
        pads.push((1, pad(&*argon, &header, 1)));
    }
    for (x, prf) in prfs {
        pads.push((*x, pad(prf, &header, *x)));
    }
    let (record, paper) = seal(&header, &pads, entropy, &mut os_random)?;
    let paper: Shares = Zeroizing::new(paper);

    // One factor per share (pad or paper share), by x, so share i is all[i].
    let mut all: Shares = Zeroizing::new(Vec::with_capacity(n));
    all.extend_from_slice(&pads);
    all.extend_from_slice(&paper);
    all.sort_unstable_by_key(|s| s.0); // in place: unlike the stable sort, no scratch buffer to leave behind
    for c in combinations(n, k) {
        let factors: Shares = Zeroizing::new(c.iter().map(|&i| all[i]).collect());
        if *Zeroizing::new(unseal(&record, &factors)?.0) != entropy {
            return Err("self-check failed: nothing was saved, do not use this backup".into());
        }
    }
    println!("Self-check passed: every combination of {k} opens the record.");
    Ok((record, paper))
}

fn paper_words(paper: &Shares, x: u8) -> Zeroizing<String> {
    let share = paper
        .iter()
        .find(|s| s.0 == x)
        .expect("seal returns every paper share");
    Zeroizing::new(entropy_to_words(&share.1))
}

/// One YubiKey share: its credential (made now or pasted) and its secret. A missing or wrong key, two keys
/// plugged in or a wrong PIN is retried here, before the seed is typed. `earlier` holds the (label,
/// credential id) of the YubiKey shares already done.
fn yubikey_share(
    label: &str,
    earlier: &[(&str, &str)],
    device: Option<&str>,
    one_at_a_time: bool,
) -> Result<(String, Zeroizing<[u8; 32]>), String> {
    for _ in 0..TRIES {
        if one_at_a_time {
            pause(&format!("Plug in only {label}, then press Enter."))?;
        }
        match try_yubikey(label, earlier, device) {
            Ok(done) => return Ok(done),
            // fido::device_path refuses to guess between keys; the owner only has to unplug one.
            Err(e) if e.starts_with("several FIDO2 keys found") => println!(
                "More than one key is plugged in: unplug the other keys, leave only {label}, and try again."
            ),
            Err(e) => println!("{e}"),
        }
    }
    Err(format!("{label} was not set up; nothing was saved"))
}

fn try_yubikey(
    label: &str,
    earlier: &[(&str, &str)],
    device: Option<&str>,
) -> Result<(String, Zeroizing<[u8; 32]>), String> {
    let pasted = ask(&format!(
        "Paste the credential id if {label} already has one from `vault`, or press Enter to make a new one: "
    ))?;
    let made = pasted.is_empty();
    let cred = if made {
        println!("Making a credential: enter the YubiKey PIN, then touch the key when it blinks.");
        let new = fido::enroll(device)?;
        println!("credential id: {new}\n(it is saved on the recovery sheet; it is not secret)");
        new
    } else {
        fido::check_cred_id(&pasted)?; // a typo is found now, not after the seed and the papers
        pasted
    };
    if let Some((other, _)) = earlier.iter().find(|(_, c)| *c == cred) {
        return Err(format!(
            "that credential id is already {other}'s: each YubiKey share needs its own key"
        ));
    }
    // Each YubiKey share must be a different physical key: otherwise a missed swap, or a pasted id that is
    // really on an earlier key, puts two shares on one key while the self-check still passes and the score
    // calls the setup strong. The key's listing must hold this share's credential and none of an earlier
    // share's. It is asked for only once this share's credential exists: on a key with no credential for the
    // rp id the tool may fail, not list nothing. The first key needs no listing: `fido::secret` below fails
    // for a pasted id that is not on it.
    if !earlier.is_empty() {
        println!("Checking which key this is: enter the YubiKey PIN (no touch needed).");
        let listed = fido::credentials(device)?;
        let unused = if made {
            " (the credential just made on it is unused and does no harm)"
        } else {
            ""
        };
        if let Some((other, _)) = earlier.iter().find(|(_, c)| listed.iter().any(|l| l == c)) {
            return Err(format!(
                "this is the same key as {other}; plug in {label}{unused}"
            ));
        }
        if !listed.contains(&cred) {
            return Err(format!(
                "credential {cred} is not on this key: plug in {label}, or paste the id made on it"
            ));
        }
    }
    println!("Enter the YubiKey PIN, then touch the key when it blinks.");
    let secret = Zeroizing::new(fido::secret(&cred, device).map_err(|e| {
        // Unlisted, a pasted id may simply not be on this key: the tool's failure cannot tell that from a
        // wrong PIN, so both are named.
        if !made && earlier.is_empty() && e.starts_with("fido2-assert failed") {
            format!(
                "{e}\nIf the PIN was right, this credential id is not on the plugged-in key: plug in {label}, or paste the id made on it."
            )
        } else {
            e
        }
    })?);
    Ok((cred, secret))
}

pub fn backup(setup: Option<String>, device: Option<String>) -> Result<(), String> {
    // A plan file is untrusted input: it is refused here, before a folder is made or a secret is typed.
    let planned = match &setup {
        Some(path) => {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
            Some((path, Layout::parse_plan(&text)?))
        }
        None => None,
    };
    let layout = match planned {
        Some((path, layout)) => {
            clear();
            println!(
                "Setup from {path} (places were checked in vault plan; only the scores that need none are shown):"
            );
            if !setup::review(&layout, None)? {
                return Err(
                    "setup not accepted: nothing was made. Change it with `vault plan`.".into(),
                );
            }
            layout
        }
        // The places asked for here only score the setup: dropped at once, never saved.
        None => setup::choose()?.0,
    };
    // --device names one path, so every key would be read there; several keys are plugged in one at a time.
    let yubikeys = layout
        .shares
        .iter()
        .filter(|s| s.kind == ShareKind::YubiKey)
        .count();
    if device.is_some() && yubikeys > 1 {
        return Err(format!(
            "--device names one key, but this setup has {yubikeys} YubiKeys: run it without --device, and \
             plug in one key at a time when asked. Nothing was made."
        ));
    }
    let dir = output_dir()?;

    let (n, k) = (layout.n(), layout.k);
    let of = |wanted: fn(&ShareKind) -> bool| -> Vec<usize> {
        (0..n).filter(|&i| wanted(&layout.shares[i].kind)).collect()
    };
    let keys = of(|s| *s == ShareKind::YubiKey);
    let papers = of(|s| matches!(s, ShareKind::Paper | ShareKind::OnePassword { .. }));
    let has_pass = layout.shares[0].kind == ShareKind::Passphrase;
    let label = |i: usize| layout.shares[i].label.as_str();

    // The step list, so the screen can say "i/N" with N from this setup.
    let mut steps: Vec<&str> = keys.iter().map(|&i| label(i)).collect();
    steps.push("seed");
    if has_pass {
        steps.push("passphrase");
    }
    steps.push("build, check and save the public files");
    steps.extend(papers.iter().map(|&i| label(i)));
    steps.push("next steps");
    let total = steps.len();
    let mut at = 0;
    let mut heading = |title: &str, secret: bool| {
        at += 1;
        step(at, total, title, secret);
    };

    clear();
    println!(
        "Seed backup: {} (any {k} restore your seed).\n",
        layout.summary()
    );
    let overview: Vec<String> = steps
        .iter()
        .enumerate()
        .map(|(i, s)| format!("{} {s}", i + 1))
        .collect();
    println!("Steps: {}\n", overview.join("  "));
    println!("Before you start:");
    println!("  - go OFFLINE (turn off wifi and unplug ethernet) and close other apps");
    let mut ready = vec!["paper and a pen"];
    ready.extend(keys.iter().map(|&i| label(i)));
    println!("  - have ready: {}", ready.join(", "));
    println!("  - nobody should be able to see the screen\n");
    println!("The public files will be saved in ./{dir}/ (checked writable).");
    pause("Press Enter when you are offline and ready.")?;

    // The keys first: a missing key or a wrong PIN fails before the seed is typed.
    let mut creds: Vec<Option<String>> = vec![None; n];
    // Never reallocates: a move would leave an unwiped copy of a key's secret.
    let mut prfs: Shares = Zeroizing::new(Vec::with_capacity(keys.len()));
    // The key is found by listing, which refuses to pick between two: one at a time (--device was refused).
    let one_at_a_time = keys.len() > 1;
    for (done, &i) in keys.iter().enumerate() {
        let x = i as u8 + 1;
        println!();
        heading(&format!("{} (share {x})", label(i)), false);
        let earlier: Vec<(&str, &str)> = keys[..done]
            .iter()
            .map(|&j| (label(j), creds[j].as_deref().expect("set above")))
            .collect();
        let (cred, secret) = yubikey_share(label(i), &earlier, device.as_deref(), one_at_a_time)?;
        prfs.push((x, *secret));
        creds[i] = Some(cred);
    }

    println!();
    heading("Seed (typed hidden, twice)", true);
    let entropy = enter_seed()?;

    // Generated, shown once, then proven.
    let pass = if has_pass {
        let pass = Zeroizing::new(new_passphrase(12));
        clear();
        heading("Passphrase (12 generated words)", true);
        println!("Write it on paper now, in lowercase, one space between words.");
        println!("Keep it apart from the other shares. It is NOT a wallet seed.\n");
        show_words("passphrase:", &pass);
        println!();
        pause("Press Enter once it is written down; the screen will be cleared.")?;
        confirm_passphrase(&pass)?;
        Some(pass)
    } else {
        None
    };

    clear();
    heading("Building, checking and saving the backup", false);
    let (record, paper) =
        build_record(&entropy, pass.as_ref().map(|p| p.as_str()), &layout, &prfs)?;

    // Saved now, before any share leaves this process: once papers exist, the record they belong to must
    // be on disk. 1Password item names are fixed by the record id, so the sheet can name them.
    let fingerprint = seed_fingerprint(&entropy);
    save(
        &format!("{dir}/record.hex"),
        &format!("0x{}\n", hex(&record)),
    )?;
    save(
        &format!("{dir}/recovery-sheet.txt"),
        &sheet::render(&record, &layout, &creds, &fingerprint),
    )?;
    println!("Saved two PUBLIC files in ./{dir}/ : record.hex and recovery-sheet.txt");

    for &i in &papers {
        let x = i as u8 + 1;
        let words = paper_words(&paper, x);
        println!();
        let title = if let ShareKind::OnePassword { .. } = layout.shares[i].kind {
            heading(
                &format!(
                    "{} (share {x}) for 1Password (24 words, TEMPORARY paper)",
                    label(i)
                ),
                true,
            );
            println!(
                "Write it on its own paper, labelled \"share {x}, for 1Password, destroy after `vault op-store`\"."
            );
            println!("Never keep it with another share: any {k} shares restore the seed.\n");
            format!("share {x} for 1Password (TEMPORARY paper):")
        } else {
            heading(&format!("{} (share {x}, 24 words)", label(i)), true);
            println!("Write it on paper, kept apart from the other shares.");
            println!(
                "These 24 words look like a wallet seed but are NOT one. Label the paper \"backup share {x}, not a wallet\".\n"
            );
            format!("paper share (this is share {x}):")
        };
        show_words(&title, &words);
        println!();
        pause("Press Enter once it is written down; you will type all 24 words back.")?;
        confirm_paper_share(x, &words).map_err(|e| {
            format!("{e}. This backup is NOT usable: delete ./{dir}/, destroy every paper written in this run, and start again.")
        })?;
        clear();
    }

    heading(
        &format!(
            "Backup made. Seed fingerprint: {fingerprint}   record id: {}",
            record_id(&record)
        ),
        false,
    );
    println!();
    let in_1password: Vec<usize> = papers
        .iter()
        .copied()
        .filter(|&i| matches!(layout.shares[i].kind, ShareKind::OnePassword { .. }))
        .collect();
    let mut todo = vec![format!(
        "TEST your shares now, offline: run `vault restore`, pick \"Verify only\" and try combinations of\n     \
         {k} shares until every share has been used. Each must show fingerprint {fingerprint}. The seed is never shown."
    )];
    if !in_1password.is_empty() {
        todo[0].push_str(
            "\n     For a 1Password share, answer no to reading it from 1Password and type its temporary paper.",
        );
    }
    for &i in &in_1password {
        let x = i + 1;
        todo.push(format!(
            "on your online machine with 1Password (never this one), put share {x} (\"{}\") into 1Password:\n       \
             vault op-store {dir}/recovery-sheet.txt\n     \
             then DESTROY the temporary share-{x} paper (shred or burn it)",
            label(i)
        ));
    }
    todo.push(format!(
        "on an online machine, store the record on a chain (no secrets needed):\n       \
         publish <rpc-url> {dir}/record.hex <refund-address>\n     \
         it deploys the record as contract code from a throwaway key and prints chain id and address"
    ));
    todo.push(
        "write chain id and address on the recovery sheet; keep several copies, and put a copy of the\n     \
         record (or the sheet) with these locators in the storage place of each share too"
            .to_string(),
    );
    println!("Next:");
    for (i, item) in todo.iter().enumerate() {
        println!("  {}. {item}", i + 1);
    }
    Ok(())
}

/// `vault op-store`: the online half of a 1Password share. The share is typed (twice) from its temporary
/// paper and stored in the item the recovery sheet names, then read back through the path a restore uses.
/// Only that one share is ever on this machine, which is why it may be online.
pub fn op_store(sheet_path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(sheet_path)
        .map_err(|e| format!("cannot read {sheet_path}: {e}"))?;
    // (x, label, reference, account) of each 1Password share; old sheets name share 2 with no label.
    let mut shares: Vec<(u8, String, String, String)> = sheet::parse(&text)
        .into_iter()
        .filter_map(|s| match s.locator {
            Locator::OnePassword { reference, account } => Some((s.x, s.label, reference, account)),
            _ => None,
        })
        .collect();
    let pick = match shares.len() {
        0 => {
            return Err(
                "this recovery sheet names no 1Password share (was the backup made with a YubiKey?)"
                    .into(),
            );
        }
        1 => 0,
        _ => {
            let items: Vec<String> = shares
                .iter()
                .map(|(x, label, ..)| format!("share {x}: {label}"))
                .collect();
            let items: Vec<&str> = items.iter().map(String::as_str).collect();
            choose("Which 1Password share?", &items)?
        }
    };
    // The item title, epn-share-<x>-<record id>, comes from the sheet's reference: restore reads that same
    // reference, so the share must be stored under it exactly.
    let (x, _, reference, account) = shares.swap_remove(pick);
    let (vault, title) = onepassword::split_reference(&reference)?;
    clear();
    println!(
        "Store share {x} in 1Password: account {account}, vault \"{vault}\", item \"{title}\"."
    );
    println!(
        "Type it from the temporary paper. Only share {x} goes here: never the seed or another share.\n"
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
    match onepassword::read(&account, &reference) {
        Ok(existing) if *existing == *words => {
            println!(
                "Share {x} is already in 1Password as {reference} (checked). Now destroy the temporary share-{x} paper."
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
    let stored = onepassword::store(&account, vault, title, &words)?;
    // Read back through the same path a restore uses: a wrong vault, a sync problem or a template
    // 1Password does not accept is caught now and not on the day the share is needed.
    let back = onepassword::read(&account, &stored).map_err(|e| {
        format!("{e}\nThe item \"{title}\" may now exist: check vault \"{vault}\" and delete it before running this again.")
    })?;
    if *back != *words {
        return Err(format!(
            "the item read back is not the share typed: delete the item \"{title}\" and run this again"
        ));
    }
    println!("Share {x} is in 1Password as {stored} (read back and checked).");
    println!(
        "Now destroy the temporary share-{x} paper (shred or burn it): with other shares it would restore the seed."
    );
    Ok(())
}
