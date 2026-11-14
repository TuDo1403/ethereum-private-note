//! `vault`: the guided backup and restore. Backup walks through the offline half step by step and leaves
//! two public files (the record and a recovery sheet); sending the record to a chain is a separate, online
//! step that never needs a secret. Restore asks which two factors you have and walks through each.
//!
//! Secrets (seed, passphrase, share C, YubiKey secret) live in memory only, wrapped in `Zeroizing` where the
//! type allows. That is best effort: copies made by the format crate's helpers are not wiped. The real
//! protection is running this on an offline machine and clearing the screen after each secret is shown.
//!
//! Nothing here is needed to restore: `recover` and SPEC.md stand alone.

use epn_core::*;
use std::io::{IsTerminal, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

fn ask(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut s = String::new();
    match std::io::stdin().read_line(&mut s) {
        Ok(0) => Err("input closed".into()),
        Ok(_) => Ok(s.trim().to_string()),
        Err(e) => Err(e.to_string()),
    }
}

// Reads from the tty with echo off.
fn ask_hidden(prompt: &str) -> Result<Zeroizing<String>, String> {
    rpassword::prompt_password(prompt).map(Zeroizing::new).map_err(|e| e.to_string())
}

fn pause(msg: &str) -> Result<(), String> {
    ask(msg).map(|_| ())
}

// Also clears the scrollback (3J), so a secret does not stay one scroll away.
fn clear() {
    print!("\x1b[2J\x1b[3J\x1b[H");
    std::io::stdout().flush().ok();
}

fn show_words(title: &str, words: &str) {
    println!("{title}");
    for (i, w) in words.split(' ').enumerate() {
        println!("  {:>2}. {w}", i + 1);
    }
}

/// Make the user prove the passphrase is written down, exactly: restore does not normalise it.
fn confirm_passphrase(pass: &str) -> Result<(), String> {
    for _ in 0..3 {
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

/// All 24 share C words must be typed back from the paper and match: a quiz on a few words would let a
/// miswritten word through, and share C has no other check until the day it is needed.
fn confirm_share_c(words: &str) -> Result<(), String> {
    for _ in 0..3 {
        clear();
        println!("Now type share C back from your paper, all 24 words (hidden).");
        if *enter_share_c()? == words {
            return Ok(());
        }
        println!("That is not the share C shown: some word on the paper is wrong or out of order.");
        show_words("Share C again (correct the paper carefully):", words);
        pause("Press Enter to type it again.")?;
    }
    Err("share C not confirmed".into())
}

/// The scripted restore, safe to type: secrets go to hidden `read` prompts, never onto a command line
/// (where shell history would keep them). Line 1 is share C, line 2 the passphrase; Enter leaves one out.
const RECOVER_SAFE: &str =
    "IFS= read -rs C; IFS= read -rs P; printf '%s\\n%s' \"$C\" \"$P\" | recover restore <record>; unset C P";

fn sheet(record: &[u8], cred_id: &str, fingerprint: &str) -> String {
    let record_hex: String = record.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "Recovery sheet. Nothing here is secret: keep several copies (paper, email, cloud).\n\n\
         record id:        {id}   (SHA-256 of the record, first 8 bytes; `publish` prints the same id)\n\
         record:           0x{record_hex}\n\
         seed fingerprint: {fingerprint}   (a verify-only restore must show the same)\n\
         credential:       {cred_id}   (YubiKey, rpId localhost)\n\n\
         Where the record is stored on chain:\n\
         contract:         {BLOBSTORE_ADDRESS}   (BlobStore, the same on every chain)\n\
         chain id:         ________\n\
         sender:           __________________________________________\n\n\
         read:     cast call {BLOBSTORE_ADDRESS} \"records(address)(bytes)\" <sender> --rpc-url <rpc>\n\
         restore:  vault restore   (guided, hidden prompts; choose \"verify only\" for a test restore)\n\
         scripted: {RECOVER_SAFE}\n\
         \x20         (add --cred-id {cred_id} to use the YubiKey; type share C, Enter, passphrase, Enter:\n\
         \x20         nothing is shown and nothing reaches shell history)\n\
         format:   SPEC.md (print it with this sheet)\n\n\
         Any two of: passphrase, YubiKey (+ its PIN), share C restore the seed.\n\
         Keep a copy of the record (or this sheet) with the contract, chain id, sender and record id in the\n\
         storage place of each factor too, so any two factors arrive with what they need.\n",
        id = record_id(record),
    )
}

fn yes(prompt: &str) -> Result<bool, String> {
    loop {
        match ask(&format!("{prompt} [y/n]: "))?.to_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer y or n."),
        }
    }
}

/// The record, from a pasted hex string or a record.hex file. A recovery-sheet.txt beside the file
/// supplies the YubiKey credential id, so the user does not have to find it.
fn read_record() -> Result<(Vec<u8>, Option<String>), String> {
    for _ in 0..3 {
        let input = ask("Paste the record (0x...) or the path to record.hex: ")?;
        let path = std::path::Path::new(&input);
        let (text, cred) = if path.is_file() {
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let cred = std::fs::read_to_string(path.with_file_name("recovery-sheet.txt")).ok().and_then(|s| {
                s.lines().find_map(|l| l.strip_prefix("credential:")?.split_whitespace().next().map(str::to_string))
            });
            (text, cred)
        } else {
            (input.clone(), None)
        };
        match unhex(&text) {
            Ok(r) if r.len() == RECORD && r[0] == 1 => return Ok((r, cred)),
            _ => println!("That is not a v1 record ({RECORD} bytes of hex)."),
        }
    }
    Err("no valid record given".into())
}

/// Share C one word at a time, so a typo is caught on the spot and not after a full Argon2 run. The
/// first letters are enough (BIP39 words are unique by their first four). Input is hidden: it is a secret.
fn enter_share_c() -> Result<Zeroizing<String>, String> {
    let mut words: Vec<&'static str> = Vec::new();
    while words.len() < 24 {
        let typed = ask_hidden(&format!("share C word {}/24 (3+ letters are enough): ", words.len() + 1))?;
        match complete_word(&typed) {
            Some(w) => words.push(w),
            None => println!("  not a BIP39 word, or too short to be unique: type it again"),
        }
    }
    loop {
        let joined = Zeroizing::new(words.join(" "));
        let Err(e) = share_c_from_words(&joined) else { return Ok(joined) };
        // The checksum says some word is wrong but not which one, so the user picks.
        println!("\n{e}");
        let n: usize = ask("Which word number (1-24) do you want to type again? ")?.parse().unwrap_or(0);
        if !(1..=24).contains(&n) {
            continue;
        }
        loop {
            let typed = ask_hidden(&format!("share C word {n}/24: "))?;
            if let Some(w) = complete_word(&typed) {
                words[n - 1] = w;
                break;
            }
            println!("  not a BIP39 word, or too short to be unique: type it again");
        }
    }
}

fn restore_flow(device: Option<String>) -> Result<(), String> {
    clear();
    println!("Restore your seed. You need the record and any TWO of: passphrase, YubiKey (+ its PIN), share C.\n");
    println!("  1. restore: show the seed words (do this offline, nobody watching the screen)");
    println!("  2. verify only: check two factors and show the seed fingerprint, never the seed\n");
    let verify_only = loop {
        match ask("1 or 2: ")?.as_str() {
            "1" => break false,
            "2" => break true,
            _ => {}
        }
    };
    let (record, sheet_cred) = read_record()?;

    let (use_pass, use_key, use_c) = loop {
        println!("\nWhich do you have with you?");
        let have = (yes("  passphrase")?, yes("  YubiKey and its PIN")?, yes("  share C (24 words)")?);
        if [have.0, have.1, have.2].iter().filter(|b| **b).count() >= 2 {
            break have;
        }
        println!("Any two are needed; with fewer the seed cannot be restored.");
    };

    // The key first when used: a missing key or a wrong PIN should fail before any typing.
    let prf = if use_key {
        let cred = match sheet_cred {
            Some(c) => c,
            None => ask("YubiKey credential id (from your recovery sheet): ")?,
        };
        println!("\nEnter the YubiKey PIN, then touch the key when it blinks.");
        Some(Zeroizing::new(fido::secret(&cred, device.as_deref())?))
    } else {
        None
    };

    let (mut share_c, mut pass) = (None, None);
    let (mut redo_c, mut redo_p) = (use_c, use_pass);
    for attempt in 1..=3 {
        if redo_c {
            println!();
            share_c = Some(enter_share_c()?);
        }
        if redo_p {
            pass = Some(ask_hidden("passphrase, exactly as written (hidden): ")?);
        }
        if pass.is_some() {
            println!("Stretching the passphrase (Argon2id, 1 GiB; takes a while)...");
        }
        let opened = restore(
            &record,
            pass.as_ref().map(|p| p.as_str()),
            prf.as_ref().map(|p| p.as_slice()),
            share_c.as_ref().map(|s| s.as_str()),
        );
        match opened {
            Ok((words, used)) => {
                let words = Zeroizing::new(words);
                if verify_only {
                    let entropy = Zeroizing::new(words_to_entropy(&words)?);
                    println!("\nVerified: {used} open the record.");
                    println!("Seed fingerprint: {}", seed_fingerprint(&entropy));
                    println!("It must match the fingerprint on your recovery sheet (and the one shown at backup).");
                    return Ok(());
                }
                clear();
                println!("Restored using {used}. Your seed:\n");
                show_words("seed:", &words);
                println!();
                pause("Write it down, then press Enter: the screen will be cleared.")?;
                clear();
                return Ok(());
            }
            Err(e) => {
                println!("\n{e}");
                if attempt == 3 {
                    return Err("not restored".into());
                }
                println!("Passphrase: lowercase, one space between words, exactly as written. Share C: words in order.");
                redo_p = use_pass && yes("Type the passphrase again?")?;
                redo_c = use_c && yes("Enter share C again?")?;
                if !redo_p && !redo_c {
                    return Err("not restored".into());
                }
            }
        }
    }
    Err("not restored".into())
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let device = match args.iter().position(|a| a == "--device") {
        Some(i) if i + 1 < args.len() => {
            args.remove(i);
            Some(args.remove(i))
        }
        Some(_) => return Err("--device needs a value".into()),
        None => None,
    };
    let mode = match args.as_slice() {
        [] => None,
        [m] if m == "backup" || m == "restore" => Some(m.clone()),
        _ => return Err("usage: vault [backup|restore] [--device PATH]".into()),
    };
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("vault is interactive: run it in a terminal, not through a pipe".into());
    }
    let mode = match mode {
        Some(m) => m,
        None => {
            clear();
            println!("What do you want to do?\n  1. make a new backup of a seed\n  2. restore a seed from a backup\n");
            loop {
                match ask("1 or 2: ")?.as_str() {
                    "1" => break "backup".to_string(),
                    "2" => break "restore".to_string(),
                    _ => {}
                }
            }
        }
    };
    if mode == "backup" { backup(device) } else { restore_flow(device) }
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
        format!("cannot write {path}: {e}\nThe backup is NOT saved. Destroy the papers written in this run (passphrase, share C) and start again.")
    })
}

/// The seed, typed twice. BIP39's checksum is only 4 bits for 12 words (8 for 24), so a typo that is
/// another list word ("wave" for "wage") passes it one time in 16 and would be backed up silently.
/// Both entries must give the same entropy.
fn enter_seed() -> Result<Zeroizing<Vec<u8>>, String> {
    for _ in 0..3 {
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

fn backup(device: Option<String>) -> Result<(), String> {
    // The output folder is made and test-written before any secret is typed or shown: a read-only or
    // full disk must stop the backup here, not after the papers exist.
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let dir = format!("backup-{stamp}");
    std::fs::create_dir(&dir).map_err(|e| format!("cannot create {dir}: {e}"))?;
    let probe = format!("{dir}/.write-test");
    std::fs::write(&probe, "test").and_then(|_| std::fs::remove_file(&probe)).map_err(|e| format!("cannot write in {dir}: {e}"))?;

    clear();
    println!("2-of-3 seed backup: passphrase + YubiKey + share C (any two restore your seed).\n");
    println!("Steps: 1 YubiKey  2 seed  3 passphrase  4 build, check and save the public files  5 share C  6 next steps\n");
    println!("Before you start:");
    println!("  - go OFFLINE (turn off wifi and unplug ethernet) and close other apps");
    println!("  - have paper and a pen ready, and the YubiKey plugged in");
    println!("  - nobody should be able to see the screen\n");
    println!("The public files will be saved in ./{dir}/ (checked writable).");
    pause("Press Enter when you are offline and ready.")?;

    // 1. YubiKey credential
    println!("\n1/6 YubiKey");
    let id = ask("Paste the credential id if this key already has one from `vault`, or press Enter to make a new one: ")?;
    let cred_id = if id.is_empty() {
        println!("Making a credential: enter the YubiKey PIN, then touch the key when it blinks.");
        let new = fido::enroll(device.as_deref())?;
        println!("credential id: {new}\n(it is saved on the recovery sheet; it is not secret)");
        new
    } else {
        id
    };

    // 2. seed
    println!("\n2/6 Seed");
    let entropy = enter_seed()?;

    // 3. passphrase: generated, shown once, then proven
    let pass = Zeroizing::new(new_passphrase(7, &mut os_random));
    clear();
    println!("3/6 Passphrase (7 generated words). Write it on paper now, in lowercase, one space between words.");
    println!("Keep it apart from share C and from the YubiKey. It is NOT a wallet seed.\n");
    show_words("passphrase:", &pass);
    println!();
    pause("Press Enter once it is written down; the screen will be cleared.")?;
    confirm_passphrase(&pass)?;

    // 4. build
    clear();
    println!("4/6 Building the backup.");
    println!("Enter the YubiKey PIN, then touch the key when it blinks.");
    let prf = Zeroizing::new(fido::secret(&cred_id, device.as_deref())?);
    let header = new_header(ARGON_M_KIB, ARGON_T, &os_random(16));
    println!("Stretching the passphrase (Argon2id, 1 GiB; takes a while)...");
    let pad_a = Zeroizing::new(derive_pad_a(&pass, &header)?.1);
    let pad_b = Zeroizing::new(derive_pad_b(&*prf, &header)?);
    let (record, share_c) = seal(&header, &pad_a, &pad_b, &entropy, &mut os_random)?;
    let share_c = Zeroizing::new(share_c);

    // Every pair must open the record before anything is saved.
    for f in [
        Factors { a: Some(*pad_a), b: Some(*pad_b), c: None },
        Factors { a: Some(*pad_a), b: None, c: Some(*share_c) },
        Factors { a: None, b: Some(*pad_b), c: Some(*share_c) },
    ] {
        if unseal(&record, &f)?.0 != *entropy {
            return Err("self-check failed: nothing was saved, do not use this backup".into());
        }
    }
    println!("Self-check passed: every pair of factors opens the record.");

    // Saved now, before share C is shown: once papers exist, the record they belong to must be on disk.
    let fingerprint = seed_fingerprint(&entropy);
    let record_hex: String = record.iter().map(|b| format!("{b:02x}")).collect();
    save(&format!("{dir}/record.hex"), &format!("0x{record_hex}\n"))?;
    save(&format!("{dir}/recovery-sheet.txt"), &sheet(&record, &cred_id, &fingerprint))?;
    println!("Saved two PUBLIC files in ./{dir}/ : record.hex and recovery-sheet.txt");

    // 5. share C
    let share_words = Zeroizing::new(entropy_to_words(&*share_c));
    println!("\n5/6 Share C (24 words). Write it on paper, in a different place from the passphrase.");
    println!("These 24 words look like a wallet seed but are NOT one. Label the paper \"backup share, not a wallet\".\n");
    show_words("share C:", &share_words);
    println!();
    pause("Press Enter once it is written down; you will type all 24 words back.")?;
    confirm_share_c(&share_words).map_err(|e| {
        format!("{e}. This backup is NOT usable: delete ./{dir}/, destroy the passphrase and share C papers, and start again.")
    })?;
    clear();

    // 6. next steps
    println!("6/6 Backup made. Seed fingerprint: {fingerprint}   record id: {}\n", record_id(&record));
    println!("Next:");
    println!("  1. TEST your papers now, offline: run `vault restore`, choose 2 (verify only) and use the passphrase");
    println!("     and share C papers. It must show fingerprint {fingerprint}. The seed is never shown.");
    println!("  2. on an online machine, store the record on a chain (no secrets needed):");
    println!("       publish <rpc-url> {dir}/record.hex <refund-address>");
    println!("     it pays from a throwaway key, not one tied to your seed, and prints chain id and sender");
    println!("  3. write chain id and sender on the recovery sheet (contract {BLOBSTORE_ADDRESS} is prefilled);");
    println!("     keep several copies, and put a copy of the record (or the sheet) with these locators in the");
    println!("     storage place of each factor paper too");
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
