//! `vault restore`: asks which factors you hold and walks through each, for any record the format allows.
//! Secrets are read at hidden prompts; "verify only" prints the seed fingerprint and never the seed.

use crate::onepassword;
use crate::prompt::*;
use epn_core::bip39::words_to_entropy;
use epn_core::record::{Header, Kind, parse_record, restore};
use epn_core::{fido, seed_fingerprint, unhex};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// What a recovery-sheet.txt beside record.hex tells the restore: the YubiKey credential id and the
/// 1Password references of shares kept there, so the user does not have to find them.
#[derive(Default)]
struct SheetHints {
    cred: Option<String>,
    op_refs: Vec<onepassword::SheetRef>,
}

/// The record, from a pasted hex string or a record.hex file (with the hints of the sheet beside it).
fn read_record() -> Result<(Vec<u8>, Header, SheetHints), String> {
    for _ in 0..TRIES {
        let input = ask("Paste the record (0x...) or the path to record.hex: ")?;
        let path = std::path::Path::new(&input);
        let (text, hints) = if path.is_file() {
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let sheet = std::fs::read_to_string(path.with_file_name("recovery-sheet.txt"))
                .unwrap_or_default();
            let cred = sheet.lines().find_map(|l| {
                l.strip_prefix("credential:")?
                    .split_whitespace()
                    .next()
                    .map(str::to_string)
            });
            (
                text,
                SheetHints {
                    cred,
                    op_refs: onepassword::sheet_references(&sheet),
                },
            )
        } else {
            (input.clone(), SheetHints::default())
        };
        match unhex(&text).and_then(|r| parse_record(&r).map(|h| (r, h))) {
            Ok((r, h)) => return Ok((r, h, hints)),
            Err(e) => println!("That is not a record: {e}"),
        }
    }
    Err("no valid record given".into())
}

fn label(kind: Kind, in_1password: bool) -> &'static str {
    match kind {
        Kind::Passphrase => "passphrase",
        Kind::Hardware => "YubiKey and its PIN",
        Kind::Paper if in_1password => "1Password item (Touch ID)",
        Kind::Paper => "paper share (24 words)",
    }
}

pub fn restore_flow(device: Option<String>) -> Result<(), String> {
    clear();
    println!(
        "Restore your seed. You need the record and enough of its factors (2 of 3 for a backup made by `vault`).\n"
    );
    println!("  1. restore: show the seed words (do this offline, nobody watching the screen)");
    println!("  2. verify only: check the factors and show the seed fingerprint, never the seed\n");
    let verify_only = choose_1_or_2()? == 2;
    let (record, h, hints) = read_record()?;
    let mut sheet_cred = hints.cred;
    let op_ref = |x: u8| hints.op_refs.iter().find(|r| r.x == x);

    let held: Vec<u8> = loop {
        println!(
            "\nThis record needs any {} of its {} factors. Which do you have with you?",
            h.k,
            h.kinds.len()
        );
        let mut held = Vec::new();
        for (i, &kind) in h.kinds.iter().enumerate() {
            let x = i as u8 + 1;
            if yes(&format!(
                "  share {x}: {}",
                label(kind, op_ref(x).is_some())
            ))? {
                held.push(x);
            }
        }
        if held.len() >= h.k {
            break held;
        }
        println!(
            "At least {} are needed; with fewer the seed cannot be restored.",
            h.k
        );
    };
    let kind = |x: u8| h.kinds[x as usize - 1];

    // The keys first: a missing key or a wrong PIN should fail before any typing.
    let mut hardware = Zeroizing::new(Vec::with_capacity(5)); // never reallocates: a move would leave an unwiped copy
    let keys: Vec<u8> = held
        .iter()
        .copied()
        .filter(|&x| kind(x) == Kind::Hardware)
        .collect();
    // The sheet names the credential of the one YubiKey `vault` enrolls; with several keys it cannot say
    // which share it belongs to, so each is asked for.
    if keys.len() != 1 {
        sheet_cred = None;
    }
    for &x in &keys {
        let cred = match sheet_cred.take() {
            Some(c) => c,
            None => ask(&format!(
                "Credential id of the YubiKey that is share {x} (from your recovery sheet): "
            ))?,
        };
        println!("\nEnter the PIN, then touch the YubiKey that is share {x} when it blinks.");
        hardware.push((x, fido::secret(&cred, device.as_deref())?));
    }

    // What is typed (passphrase, paper words) by share number, so a failed attempt can retype any of them.
    let mut typed: BTreeMap<u8, Zeroizing<String>> = BTreeMap::new();
    let mut redo: Vec<u8> = held
        .iter()
        .copied()
        .filter(|&x| kind(x) != Kind::Hardware)
        .collect();
    for attempt in 1..=TRIES {
        for &x in &redo {
            println!();
            let secret = match (kind(x), op_ref(x)) {
                (Kind::Passphrase, _) => ask_hidden("passphrase, exactly as written (hidden): ")?,
                (_, Some(r))
                    if yes(&format!(
                        "Read share {x} from 1Password ({}, account {}); it asks for Touch ID?",
                        r.reference, r.account
                    ))? =>
                {
                    onepassword::read(&r.account, &r.reference)?
                }
                _ => enter_paper_share(x)?,
            };
            typed.insert(x, secret);
        }
        let pass = typed
            .iter()
            .find(|&(&x, _)| kind(x) == Kind::Passphrase)
            .map(|(_, p)| p.as_str());
        let paper: Vec<(u8, &str)> = typed
            .iter()
            .filter(|&(&x, _)| kind(x) == Kind::Paper)
            .map(|(&x, w)| (x, w.as_str()))
            .collect();
        if pass.is_some() {
            println!("Stretching the passphrase (Argon2id, 1 GiB; takes a while)...");
        }
        match restore(&record, pass, &hardware, &paper) {
            Ok((words, used)) => {
                let words = Zeroizing::new(words);
                if verify_only {
                    let entropy = Zeroizing::new(words_to_entropy(&words)?);
                    println!("\nVerified: shares {used:?} open the record.");
                    println!("Seed fingerprint: {}", seed_fingerprint(&entropy));
                    println!(
                        "It must match the fingerprint on your recovery sheet (and the one shown at backup)."
                    );
                    return Ok(());
                }
                clear();
                println!("Restored using shares {used:?}. Your seed:\n");
                show_words("seed:", &words);
                println!();
                pause("Write it down, then press Enter: the screen will be cleared.")?;
                clear();
                return Ok(());
            }
            Err(e) => {
                println!("\n{e}");
                if attempt == TRIES {
                    break;
                }
                println!(
                    "Passphrase: lowercase, one space between words, exactly as written. Paper share: words in order."
                );
                redo = Vec::new();
                for &x in typed.keys() {
                    if yes(&format!(
                        "Enter share {x} ({}) again?",
                        label(kind(x), op_ref(x).is_some())
                    ))? {
                        redo.push(x);
                    }
                }
                if redo.is_empty() {
                    break;
                }
            }
        }
    }
    Err("not restored".into())
}
