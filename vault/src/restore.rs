//! `vault restore`: asks which factors you hold and walks through each, for any record the format allows.
//! Secrets are read at hidden prompts; "verify only" prints the seed fingerprint and never the seed.

use crate::onepassword::{self, split_reference, title};
use crate::prompt::*;
use crate::sheet::{self, Locator, SheetShare};
use epn_core::bip39::words_to_entropy;
use epn_core::record::{Header, Kind, parse_record, restore};
use epn_core::{fido, record_id, seed_fingerprint, unhex};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// The record, from a pasted hex string or a record.hex file (with the shares named by the
/// recovery-sheet.txt beside it, so the user does not have to find their credential ids and references).
fn read_record() -> Result<(Vec<u8>, Header, Vec<SheetShare>), String> {
    for _ in 0..TRIES {
        let input = ask("Paste the record (0x...) or the path to record.hex: ")?;
        let path = std::path::Path::new(&input);
        let (text, shares) = if path.is_file() {
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let sheet = std::fs::read_to_string(path.with_file_name("recovery-sheet.txt"))
                .unwrap_or_default();
            (text, sheet::parse(&sheet))
        } else {
            (input.clone(), Vec::new())
        };
        match unhex(&text).and_then(|r| parse_record(&r).map(|h| (r, h))) {
            Ok((r, h)) => return Ok((r, h, shares)),
            Err(e) => println!("That is not a record: {e}"),
        }
    }
    Err("no valid record given".into())
}

/// What a share is called in a prompt: its sheet label before what it is.
fn describe(kind: Kind, s: Option<&SheetShare>) -> String {
    let what = match (kind, s.map(|s| &s.locator)) {
        (Kind::Passphrase, _) => "passphrase",
        (Kind::Hardware, _) => "YubiKey and its PIN",
        (Kind::Paper, Some(Locator::OnePassword { .. })) => "1Password item (Touch ID)",
        (Kind::Paper, _) => "paper share (24 words)",
    };
    match s {
        Some(s) => format!("{} ({what})", s.label),
        None => what.to_string(),
    }
}

/// Offer to read share `x` from 1Password. `op` needs the network, so an offline restore declines and
/// types the words instead.
fn read_from_1password(x: u8, reference: &str, account: &str) -> Result<bool, String> {
    println!(
        "Share {x} is in 1Password. Reading it needs the network; offline, answer no and type the 24 words"
    );
    println!("the 1Password app shows on another device.");
    yes(&format!(
        "Read share {x} from 1Password ({reference}, account {account}); it asks for Touch ID?"
    ))
}

/// Share `x` from 1Password when the sheet names it and the person agrees, else typed from paper. A failed
/// read (locked, Touch ID cancelled, offline) falls back to typing: a restore is done under stress and must
/// not end here after the YubiKey PIN and touch.
fn paper_share(x: u8, s: Option<&SheetShare>) -> Result<Zeroizing<String>, String> {
    if let Some(SheetShare {
        locator: Locator::OnePassword { reference, account },
        ..
    }) = s
        && read_from_1password(x, reference, account)?
    {
        match onepassword::read(account, reference) {
            Ok(words) => return Ok(words),
            Err(e) => println!("{e}\nType the 24 words from the paper instead."),
        }
    }
    enter_paper_share(x)
}

/// The secret of the YubiKey that is share `x`. The credential id on the sheet is final: if the key fails
/// with it, the sheet may be damaged or from another record, so the owner types the id. `device` is never
/// set when several keys are read (`check_device`).
fn key_secret(
    x: u8,
    s: Option<&SheetShare>,
    device: Option<&str>,
    one_at_a_time: bool,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let name = s.map(|s| format!(" (\"{}\")", s.label)).unwrap_or_default();
    let mut from_sheet = match s {
        Some(SheetShare {
            locator: Locator::Credential(c),
            ..
        }) => Some(c.clone()),
        _ => None,
    };
    with_key(
        &format!("the YubiKey that is share {x}{name}"),
        one_at_a_time,
        || {
            let cred = match &from_sheet {
                Some(c) => c.clone(),
                None => ask(&format!(
                    "Credential id of the YubiKey that is share {x} (from your recovery sheet): "
                ))?,
            };
            println!("\nEnter the PIN, then touch the YubiKey that is share {x} when it blinks.");
            let secret = fido::secret(&cred, device);
            // Only a failure with the key itself spends the sheet's id, not a second key left plugged in.
            if secret.as_ref().is_err_and(|e| !several_keys(e)) {
                from_sheet = None;
            }
            secret.map(Zeroizing::new)
        },
    )
}

pub fn restore_flow(device: Option<String>) -> Result<(), String> {
    clear();
    println!(
        "Restore your seed. You need the record and enough of its factors (the recovery sheet says how many).\n"
    );
    let modes = [
        "Verify only: check the factors and show the seed fingerprint, never the seed",
        "Restore: show the seed words (offline, nobody watching the screen)",
    ];
    // Verify only comes first: it is the safe default for the test restores a backup asks for.
    let verify_only = choose("What should this run do?", &modes)? == 0;
    let (record, h, sheet) = read_record()?;
    let kind = |x: u8| h.kinds[x as usize - 1];
    // The sheet is a plain file that gets copied around, so the record header decides: the first line for
    // share x is used only when x is one of the record's shares and its locator fits that share's kind.
    // A 1Password reference is also trusted only when it names the item backup stores share x under for
    // this record: a sheet from another backup must not make restore read that backup's share.
    let id = record_id(&record);
    let on_sheet = |x: u8| {
        sheet
            .iter()
            .find(|s| s.x == x)
            .filter(|s| match (kind(x), &s.locator) {
                (_, Locator::None) | (Kind::Hardware, Locator::Credential(_)) => true,
                (Kind::Paper, Locator::OnePassword { reference, .. }) => {
                    split_reference(reference).is_ok_and(|(_, t)| t == title(x, &id))
                }
                _ => false,
            })
    };

    let held: Vec<u8> = loop {
        println!(
            "\nThis record needs any {} of its {} factors. Which do you have with you?",
            h.k,
            h.kinds.len()
        );
        let mut held = Vec::new();
        for (i, &kind) in h.kinds.iter().enumerate() {
            let x = i as u8 + 1;
            if yes(&format!("  share {x}: {}", describe(kind, on_sheet(x))))? {
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

    // The keys first: a missing key or a wrong PIN should fail before any typing.
    let mut hardware = Zeroizing::new(Vec::with_capacity(5)); // never reallocates: a move would leave an unwiped copy
    let keys: Vec<u8> = held
        .iter()
        .copied()
        .filter(|&x| kind(x) == Kind::Hardware)
        .collect();
    check_device(device.as_deref(), keys.len(), "you hold")?;
    // The key is found by listing, which fails with two plugged in: one at a time.
    let one_at_a_time = keys.len() > 1;
    for &x in &keys {
        let secret = key_secret(x, on_sheet(x), device.as_deref(), one_at_a_time)?;
        hardware.push((x, *secret));
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
            let secret = match kind(x) {
                Kind::Passphrase => ask_hidden("passphrase, exactly as written (hidden): ")?,
                _ => paper_share(x, on_sheet(x))?,
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
        let opened = if pass.is_some() {
            working("Stretching the passphrase (Argon2id, 1 GiB)", || {
                restore(&record, pass, &hardware, &paper)
            })
        } else {
            restore(&record, pass, &hardware, &paper)
        };
        match opened {
            Ok((words, used)) => {
                let words = Zeroizing::new(words);
                if verify_only {
                    let entropy = Zeroizing::new(words_to_entropy(&words)?);
                    println!("\nVerified: shares {used:?} open the record.");
                    // Any pair opens the record, so a wrong share among three would pass unnoticed.
                    let unused: Vec<_> = held.iter().filter(|x| !used.contains(x)).collect();
                    if !unused.is_empty() {
                        println!(
                            "Not proven: shares {unused:?} were not needed. Test them in another run."
                        );
                    }
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
                        describe(kind(x), on_sheet(x))
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
