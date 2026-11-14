//! `vault`: the guided backup and restore. Backup walks through the offline half step by step and leaves
//! two public files (the record and a recovery sheet); sending the record to a chain is a separate, online
//! step that never needs a secret. Restore asks which two factors you have and walks through each.
//!
//! Secrets (seed, passphrase, share C, YubiKey secret) live in memory only, wrapped in `Zeroizing` where the
//! type allows. That is best effort: copies made by the format crate's helpers are not wiped. The real
//! protection is running this on an offline machine and clearing the screen after each secret is shown.
//!
//! Nothing here is needed to restore: `recover` and SPEC.md stand alone.

use backup_core::*;
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

/// Three random positions of the 24 share C words must be read back from the paper.
fn quiz_share_c(words: &str) -> Result<(), String> {
    let list: Vec<&str> = words.split(' ').collect();
    assert_eq!(list.len(), 24, "share C is always 24 words");
    for _ in 0..3 {
        let mut pos: Vec<usize> = Vec::new();
        while pos.len() < 3 {
            // 240 = 10 * 24, so rejecting 240..=255 keeps the modulo unbiased.
            let b = os_random(1)[0];
            if b < 240 && !pos.contains(&((b % 24) as usize)) {
                pos.push((b % 24) as usize);
            }
        }
        pos.sort();
        clear();
        println!("Check your paper copy of share C.");
        let mut ok = true;
        for p in pos {
            ok &= ask(&format!("word #{}: ", p + 1))?.to_lowercase() == list[p];
        }
        if ok {
            return Ok(());
        }
        println!("That did not match.");
        show_words("Share C again (write it down carefully):", words);
        pause("Press Enter to be quizzed again.")?;
    }
    Err("share C not confirmed; nothing was saved".into())
}

fn sheet(record_hex: &str, cred_id: &str) -> String {
    format!(
        "Recovery sheet. Nothing here is secret: keep several copies (paper, email, cloud).\n\n\
         record:     0x{record_hex}\n\
         credential: {cred_id}   (YubiKey, rpId localhost)\n\
         chain id: ________   contract: ________   sender: ________\n\n\
         read:       cast call $STORE \"records(address)(bytes)\" $SENDER --rpc-url $RPC\n\
         restore:    printf '%s\\n%s' \"$SHARE_C_WORDS\" \"$PASS\" | recover restore <record> --cred-id {cred_id}\n\
         format:     SPEC.md (print it with this sheet)\n\n\
         Any two of: passphrase, YubiKey (+ its PIN), share C restore the seed.\n"
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
    println!("Restore your seed. You need the record and any TWO of: passphrase, YubiKey (+ its PIN), share C.");
    println!("Do this on an offline machine: the seed will be shown on this screen.\n");
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

fn backup(device: Option<String>) -> Result<(), String> {

    clear();
    println!("2-of-3 seed backup: passphrase + YubiKey + share C (any two restore your seed).\n");
    println!("Steps: 1 YubiKey  2 seed  3 passphrase  4 build and check  5 share C  6 save the public files\n");
    println!("Before you start:");
    println!("  - go OFFLINE (turn off wifi and unplug ethernet) and close other apps");
    println!("  - have paper and a pen ready, and the YubiKey plugged in");
    println!("  - nobody should be able to see the screen\n");
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
    let mut entropy = None;
    for _ in 0..3 {
        let words = ask_hidden("Type your seed words (hidden, 12 to 24 words): ")?;
        match words_to_entropy(words.trim()) {
            Ok(e) => {
                println!("Accepted: {} words, checksum OK.", words.split_whitespace().count());
                entropy = Some(Zeroizing::new(e));
                break;
            }
            Err(e) => println!("{e}"),
        }
    }
    let entropy = entropy.ok_or("seed not accepted")?;

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

    // 5. share C
    let share_words = Zeroizing::new(entropy_to_words(&*share_c));
    println!("\n5/6 Share C (24 words). Write it on paper, in a different place from the passphrase.");
    println!("These 24 words look like a wallet seed but are NOT one. Label the paper \"backup share, not a wallet\".\n");
    show_words("share C:", &share_words);
    println!();
    pause("Press Enter once it is written down; you will be quizzed on three words.")?;
    quiz_share_c(&share_words)?;
    clear();

    // 6. public files
    let record_hex: String = record.iter().map(|b| format!("{b:02x}")).collect();
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let dir = format!("backup-{stamp}");
    std::fs::create_dir(&dir).map_err(|e| format!("cannot create {dir}: {e}"))?;
    std::fs::write(format!("{dir}/record.hex"), format!("0x{record_hex}\n")).map_err(|e| e.to_string())?;
    std::fs::write(format!("{dir}/recovery-sheet.txt"), sheet(&record_hex, &cred_id)).map_err(|e| e.to_string())?;

    println!("6/6 Saved two PUBLIC files in ./{dir}/ : record.hex and recovery-sheet.txt\n");
    println!("Next (online, no secrets needed):");
    println!("  1. send the record to a chain:");
    println!("       cast send $STORE \"store(bytes)\" $(cat {dir}/record.hex) --rpc-url $RPC --account $SENDER");
    println!("     (use a fresh sender address that is not derived from your seed)");
    println!("  2. fill chain id, contract and sender into the recovery sheet; keep several copies");
    println!("  3. TEST a restore now, with your paper, before you trust this backup:");
    println!("       printf '%s\\n%s' \"$SHARE_C_WORDS\" \"$PASS\" | recover restore $(cat {dir}/record.hex)");
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
