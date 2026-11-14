//! `vault backup`: the offline half, step by step. It leaves two public files (the record and a recovery
//! sheet); sending the record to a chain is a separate, online step that never needs a secret.
//!
//! The backup is the 2-of-3 layout: passphrase (x = 1), YubiKey (x = 2), paper share (x = 3).

use crate::prompt::*;
use epn_core::bip39::{entropy_to_words, new_passphrase, words_to_entropy};
use epn_core::record::{ARGON_M_KIB, ARGON_T, Kind, new_header, pad, seal, stretch_passphrase, unseal};
use epn_core::{fido, hex, os_random, record_id, seed_fingerprint};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const KINDS: [Kind; 3] = [Kind::Passphrase, Kind::Hardware, Kind::Paper];
const PASS_X: u8 = 1;
pub const KEY_X: u8 = 2;
const PAPER_X: u8 = 3;

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

fn sheet(record: &[u8], cred_id: &str, fingerprint: &str) -> String {
    format!(
        "Recovery sheet. Nothing here is secret: keep several copies (paper, email, cloud).\n\n\
         record id:        {id}   (SHA-256 of the record, first 8 bytes; `publish` prints the same id)\n\
         record:           0x{record}\n\
         seed fingerprint: {fingerprint}   (a verify-only restore must show the same)\n\
         credential:       {cred_id}   (YubiKey, share {KEY_X}, rpId localhost)\n\n\
         Where the record is stored on chain (printed by `publish`):\n\
         chain id:         ________\n\
         address:          __________________________________________\n\n\
         read:     cast code <address> --rpc-url <rpc>   (the code is 00, then the record)\n\
         restore:  vault restore   (guided, hidden prompts; choose \"verify only\" for a test restore)\n\
         scripted: recover restore 0x{record} --key {KEY_X}={cred_id}\n\
         \x20         then type the factor lines on stdin, Ctrl-D to end (never in the command line):\n\
         \x20           pass <passphrase>        paper {PAPER_X} <24 words>\n\
         format:   SPEC.md (print it with this sheet)\n\n\
         Any two of: passphrase, YubiKey (+ its PIN), paper share restore the seed.\n\
         Keep a copy of the record (or this sheet) with the chain id, address and record id in the\n\
         storage place of each factor too, so any two factors arrive with what they need.\n",
        id = record_id(record),
        record = hex(record),
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

/// Seals the seed under the three factors and proves that every pair opens the record before anything is
/// saved. Returns the record and the paper share. Copies of the pads made along the way are wiped on a
/// best-effort basis only (see main.rs).
fn build_record(entropy: &[u8], pass: &str, prf: &[u8; 32]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), String> {
    let header = new_header(ARGON_M_KIB, ARGON_T, &os_random(16), 2, &KINDS)?;
    println!("Stretching the passphrase (Argon2id, 1 GiB; takes a while)...");
    let argon = Zeroizing::new(stretch_passphrase(pass, &header)?);
    let pads = Zeroizing::new([(PASS_X, pad(&*argon, &header, PASS_X)), (KEY_X, pad(prf, &header, KEY_X))]);
    let (record, paper) = seal(&header, &*pads, entropy, &mut os_random)?;
    let paper = Zeroizing::new(paper);
    let all = Zeroizing::new([pads[0], pads[1], paper[0]]);
    for pair in [[0, 1], [0, 2], [1, 2]] {
        if unseal(&record, &pair.map(|i| all[i]))?.0 != entropy {
            return Err("self-check failed: nothing was saved, do not use this backup".into());
        }
    }
    println!("Self-check passed: every pair of factors opens the record.");
    Ok((record, Zeroizing::new(paper[0].1)))
}

pub fn backup(device: Option<String>) -> Result<(), String> {
    let dir = output_dir()?;

    clear();
    println!("2-of-3 seed backup: passphrase + YubiKey + paper share (any two restore your seed).\n");
    println!("Steps: 1 YubiKey  2 seed  3 passphrase  4 build, check and save the public files  5 paper share  6 next steps\n");
    println!("Before you start:");
    println!("  - go OFFLINE (turn off wifi and unplug ethernet) and close other apps");
    println!("  - have paper and a pen ready, and the YubiKey plugged in");
    println!("  - nobody should be able to see the screen\n");
    println!("The public files will be saved in ./{dir}/ (checked writable).");
    pause("Press Enter when you are offline and ready.")?;

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

    println!("\n2/6 Seed");
    let entropy = enter_seed()?;

    // Generated, shown once, then proven.
    let pass = Zeroizing::new(new_passphrase(7));
    clear();
    println!("3/6 Passphrase (7 generated words). Write it on paper now, in lowercase, one space between words.");
    println!("Keep it apart from the paper share and from the YubiKey. It is NOT a wallet seed.\n");
    show_words("passphrase:", &pass);
    println!();
    pause("Press Enter once it is written down; the screen will be cleared.")?;
    confirm_passphrase(&pass)?;

    clear();
    println!("4/6 Building the backup.");
    println!("Enter the YubiKey PIN, then touch the key when it blinks.");
    let prf = Zeroizing::new(fido::secret(&cred_id, device.as_deref())?);
    let (record, paper_share) = build_record(&entropy, &pass, &prf)?;

    // Saved now, before the paper share is shown: once papers exist, the record they belong to must be on disk.
    let fingerprint = seed_fingerprint(&entropy);
    save(&format!("{dir}/record.hex"), &format!("0x{}\n", hex(&record)))?;
    save(&format!("{dir}/recovery-sheet.txt"), &sheet(&record, &cred_id, &fingerprint))?;
    println!("Saved two PUBLIC files in ./{dir}/ : record.hex and recovery-sheet.txt");

    let share_words = Zeroizing::new(entropy_to_words(&*paper_share));
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
