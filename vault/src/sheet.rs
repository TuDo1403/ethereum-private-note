//! The recovery sheet (`recovery-sheet.txt`, saved next to `record.hex`): one line per share naming how to
//! reach it, plus the fixed text for reading the record and restoring by hand.
//!
//! The sheet is PUBLIC and gets copied around. Nothing on it is secret, and it never says where a share is
//! kept (places only score a setup while planning, see layout.rs), so `render` takes no places.
//!
//! `parse` also reads sheets made before setups were flexible: one `credential:` line (the YubiKey, share
//! 2) and `1password:` lines, so every backup made so far still restores through `vault restore`.

use crate::layout::{Layout, ShareKind};
use crate::onepassword::{check_account, reference, sheet_references, split_reference, title};
use epn_core::{hex, record_id};

/// How a share is reached, as far as the sheet can tell.
#[derive(Debug, PartialEq, Eq)]
pub enum Locator {
    /// Passphrase and paper shares: nothing to name, the person holds the words.
    None,
    /// A YubiKey share: the FIDO2 credential id.
    Credential(String),
    /// A share in 1Password: its `op://` reference and the account to read it with.
    OnePassword { reference: String, account: String },
}

#[derive(Debug, PartialEq, Eq)]
pub struct SheetShare {
    pub x: u8,
    /// Empty for shares read from an old sheet, which names no labels.
    pub label: String,
    pub locator: Locator,
}

/// The whole recovery-sheet.txt text. `creds[i]` is `Some(id)` for YubiKey share i (share x = i + 1).
pub fn render(
    record: &[u8],
    layout: &Layout,
    creds: &[Option<String>],
    fingerprint: &str,
) -> String {
    let id = record_id(record);
    let width = layout
        .shares
        .iter()
        .map(|s| s.label.chars().count() + 2)
        .max()
        .unwrap_or(0);
    let yubikeys = layout
        .shares
        .iter()
        .filter(|s| s.kind == ShareKind::YubiKey)
        .count();

    let mut lines = String::new(); // the `share N:` lines
    let mut keys = String::new(); // ` --key X=CRED` per YubiKey
    let mut stdin = Vec::new(); // what `recover restore` reads on stdin
    for (i, s) in layout.shares.iter().enumerate() {
        let x = i + 1;
        let (kind, tail) = match &s.kind {
            ShareKind::Passphrase => {
                stdin.push("pass <passphrase>".to_string());
                ("passphrase", String::new())
            }
            ShareKind::YubiKey => {
                let cred = creds
                    .get(i)
                    .and_then(Option::as_ref)
                    .expect("a credential id for every YubiKey share");
                // `recover` takes one --device, so two keys need each its own path (SPEC.md).
                let at = if yubikeys > 1 { "@<path>" } else { "" };
                keys += &format!(" --key {x}={cred}{at}");
                ("yubikey", format!("credential {cred}   (rpId localhost)"))
            }
            ShareKind::Paper => {
                stdin.push(format!("paper {x} <24 words>"));
                ("paper", String::new())
            }
            ShareKind::OnePassword { account, vault } => {
                let r = reference(vault, &title(x as u8, &id));
                stdin.push(format!(
                    "paper {x} <words from `op read --account {account} {r}`>"
                ));
                ("1password", format!("{r} account {account}"))
            }
        };
        let label = format!("\"{}\"", s.label);
        let line = format!("share {x}:  {kind:<12} {label:<width$} {tail}");
        lines += line.trim_end();
        lines.push('\n');
    }

    let stdin = if stdin.is_empty() {
        String::new() // every share is a YubiKey: nothing to type
    } else {
        format!(
            "\x20         then type the factor lines on stdin, Ctrl-D to end (never in the command line):\n\
             \x20           {}\n",
            stdin.join("   ")
        )
    };
    let labels: Vec<&str> = layout.shares.iter().map(|s| s.label.as_str()).collect();
    format!(
        "Recovery sheet. Nothing here is secret: keep several copies (paper, email, cloud).\n\n\
         record id:        {id}   (SHA-256 of the record, first 8 bytes; `publish` prints the same id)\n\
         record:           0x{record}\n\
         seed fingerprint: {fingerprint}   (a verify-only restore must show the same)\n\n\
         {lines}\n\
         Where the record is stored on chain (printed by `publish`):\n\
         chain id:         ________\n\
         address:          __________________________________________\n\n\
         read:     cast code <address> --rpc-url <rpc>   (the code is 00, then the record)\n\
         restore:  vault restore   (guided, hidden prompts; choose \"verify only\" for a test restore)\n\
         scripted: recover restore 0x{record}{keys}\n\
         {stdin}\
         format:   SPEC.md (print it with this sheet)\n\n\
         Any {k} of: {labels} restore the seed.\n\
         Keep a copy of the record (or this sheet) with the chain id, address and record id in the\n\
         storage place of each factor too, so any {k} factors arrive with what they need.\n",
        record = hex(record),
        k = layout.k,
        labels = labels.join(", "),
    )
}

/// Shares named by a sheet: the `share N:` lines of a new sheet, else the `credential:` line (share 2)
/// and `1password:` lines of an old one. A sheet is a plain file that gets copied around, so a line that
/// does not pass the checks made at backup is skipped, and nothing odd from it reaches `op` or `fido2`.
pub fn parse(sheet: &str) -> Vec<SheetShare> {
    let new: Vec<SheetShare> = sheet.lines().filter_map(parse_line).collect();
    if !new.is_empty() {
        return new;
    }
    let cred = sheet.lines().find_map(|l| {
        let cred = l
            .strip_prefix("credential:")?
            .split_whitespace()
            .next()?
            .to_string();
        Some(SheetShare {
            x: 2,
            label: String::new(),
            locator: Locator::Credential(cred),
        })
    });
    let op = sheet_references(sheet).into_iter().map(|r| SheetShare {
        x: r.x,
        label: String::new(),
        locator: Locator::OnePassword {
            reference: r.reference,
            account: r.account,
        },
    });
    cred.into_iter().chain(op).collect()
}

/// The common Unicode format characters (category Cf) that hide or reorder text: zero width and direction
/// marks, bidi embeddings and isolates, the byte order mark. Not every Cf code point; std has no category test.
fn is_format(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// `share <x>:  <kind>  "<label>"  <locator>`. The label sits between the first pair of quotes (labels
/// hold none), and the locator follows it.
fn parse_line(l: &str) -> Option<SheetShare> {
    let (x, rest) = l.strip_prefix("share ")?.split_once(':')?;
    let (kind, rest) = rest.trim_start().split_once(' ')?;
    let (label, tail) = rest.trim_start().strip_prefix('"')?.split_once('"')?;
    // The label is printed in restore prompts: a control character (ESC, CR) could rewrite the screen around
    // them, and a format character (bidi override, zero width) could disguise what is shown.
    if label.chars().any(|c| c.is_control() || is_format(c)) {
        return None;
    }
    let tail = tail.trim();
    let locator = match kind {
        "passphrase" | "paper" => Locator::None,
        "yubikey" => Locator::Credential(
            tail.strip_prefix("credential ")?
                .split_whitespace()
                .next()?
                .to_string(),
        ),
        "1password" => {
            // Vault and item names may hold spaces: the reference runs up to the last " account ".
            let (reference, after) = tail.rsplit_once(" account ")?;
            let account = after.split_whitespace().next()?;
            split_reference(reference).ok()?;
            check_account(account).ok()?;
            Locator::OnePassword {
                reference: reference.to_string(),
                account: account.to_string(),
            }
        }
        _ => return None,
    };
    Some(SheetShare {
        x: x.parse().ok()?,
        label: label.to_string(),
        locator,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{ShareSpec, presets};

    fn spec(kind: ShareKind, label: &str) -> ShareSpec {
        ShareSpec {
            kind,
            label: label.into(),
        }
    }

    // render only formats the record as hex and hashes it for the id, so any bytes will do
    const RECORD: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn new_sheet_round_trips() {
        let layout = Layout::new(
            2,
            vec![
                spec(ShareKind::Passphrase, "passphrase"),
                spec(ShareKind::YubiKey, "YubiKey A"),
                spec(ShareKind::YubiKey, "YubiKey B"),
                spec(ShareKind::Paper, "paper"),
                spec(
                    ShareKind::OnePassword {
                        account: "my.1password.com".into(),
                        vault: "Private Vault".into(),
                    },
                    "1Password A",
                ),
            ],
        )
        .unwrap();
        let creds = [
            None,
            Some("Zm9v".to_string()),
            Some("YmFy".to_string()),
            None,
            None,
        ];
        let text = render(&RECORD, &layout, &creds, "abcd1234");
        for want in [
            "share 2:  yubikey      \"YubiKey A\"   credential Zm9v",
            "share 5:  1password    \"1Password A\" op://Private Vault/epn-share-5-",
            "--key 2=Zm9v@<path>",
            "--key 3=YmFy@<path>",
            "Any 2 of: passphrase, YubiKey A",
            "pass <passphrase>   paper 4 <24 words>   paper 5 <words from `op read --account my.1password.com op://Private Vault/epn-share-5-",
        ] {
            assert!(text.contains(want), "{want:?}\n{text}");
        }
        let parsed = parse(&text);
        assert_eq!(parsed.len(), 5);
        assert_eq!(
            parsed[0],
            SheetShare {
                x: 1,
                label: "passphrase".into(),
                locator: Locator::None
            }
        );
        assert_eq!(
            parsed[1],
            SheetShare {
                x: 2,
                label: "YubiKey A".into(),
                locator: Locator::Credential("Zm9v".into())
            }
        );
        assert!(
            matches!(&parsed[4].locator, Locator::OnePassword { account, reference }
            if account == "my.1password.com"
                && *reference == format!("op://Private Vault/epn-share-5-{}/password", record_id(&RECORD)))
        );
    }

    #[test]
    fn single_key_sheet_keeps_plain_key_flag() {
        let (k, shares) = presets().swap_remove(0);
        let layout = Layout::new(k, shares).unwrap();
        let creds = [None, Some("Zm9vYmFy".to_string()), None];
        let text = render(&RECORD, &layout, &creds, "abcd1234");
        assert!(text.contains("--key 2=Zm9vYmFy"), "{text}");
        let scripted = text.lines().find(|l| l.starts_with("scripted:")).unwrap();
        assert!(!scripted.contains('@'), "{scripted}");
    }

    #[test]
    fn old_sheet_is_read() {
        let old = "credential:       Zm9vYmFy   (YubiKey, share 2, rpId localhost)\n\
                   1password:        share 2 op://Personal/epn-share-2-ab/password account my.1password.com\n";
        let p = parse(old);
        assert!(p.contains(&SheetShare {
            x: 2,
            label: String::new(),
            locator: Locator::Credential("Zm9vYmFy".into())
        }));
        assert!(p.iter().any(|s| matches!(&s.locator, Locator::OnePassword { reference, .. } if reference.ends_with("epn-share-2-ab/password"))));
    }

    #[test]
    fn odd_share_lines_are_skipped() {
        for bad in [
            "share 2:  1password    \"x\" op://Personal/a\"b/password account me@x.com\n",
            "share 2:  1password    \"x\" op://Personal/a/password account a;b\n",
            "share 2:  1password    \"x\" op://Personal/a/password\n", // no account
            "share 2:  yubikey      \"x\"\n",                          // no credential
            "share 2:  laser        \"x\"\n",
            "share two:  paper      \"x\"\n",
            "share 2:  paper        x\n",              // no quotes
            "share 2:  paper        \"a\x1b[2Jb\"\n",  // ESC
            "share 2:  paper        \"a\rb\"\n",       // CR
            "share 2:  paper        \"a\u{202E}b\"\n", // bidi override
            "share 2:  paper        \"a\u{200B}b\"\n", // zero width space
        ] {
            assert!(parse(bad).is_empty(), "{bad:?}");
        }
    }
}
