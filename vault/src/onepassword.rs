//! Share 2 kept in 1Password instead of on a YubiKey: a paper share (24 words) stored as a 1Password item
//! and read back with `op read`, which the 1Password app unlocks with Touch ID. The record format does not
//! change: to the record this is just a paper share that happens to live in a password manager.
//!
//! The words reach `op` through stdin (a JSON item template) and come back through a pipe, so they are
//! never on a command line (visible in `ps`) or in a file. Needs the 1Password app with "Integrate with
//! 1Password CLI" switched on (Settings > Developer), and the `op` command installed.
//!
//! Every call names the account (`--account`): with several accounts signed in, `op` otherwise picks
//! one itself, and a seed factor must never land in, say, an employer's account by default.

use std::io::Write;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// The share number `vault` gives the 1Password factor (the YubiKey's place in the 2-of-3 layout).
pub const X: u8 = 2;
/// The recovery-sheet line that names the item; `vault restore` reads it back from there.
pub const SHEET_PREFIX: &str = "1password:";

fn run(args: &[&str], input: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut child = Command::new("op")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // op's own messages ("unlock 1Password", errors) must reach the user
        .spawn()
        .map_err(|e| {
            format!(
                "cannot run op: {e} (install the 1Password CLI and turn on its app integration)"
            )
        })?;
    // A write error just means op exited early; its exit status below is the real answer.
    let _ = child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes());
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let stdout = Zeroizing::new(out.stdout);
    if !out.status.success() {
        return Err(
            "op failed (1Password locked, Touch ID cancelled, wrong vault or item?)".into(),
        );
    }
    Ok(stdout)
}

/// Vault and item names go into the JSON template and the `op://` reference, so only plain characters
/// are allowed: no quotes (JSON), no slash (reference separator), no control characters.
pub fn check_name(what: &str, s: &str) -> Result<(), String> {
    let ok = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || " -_.".contains(c));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{what} may only hold letters, digits, space, '-', '_' and '.'"
        ))
    }
}

/// An account as `op --account` takes it: a sign-in address, an email or an account id. No spaces.
pub fn check_account(s: &str) -> Result<(), String> {
    let ok = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c));
    if ok {
        Ok(())
    } else {
        Err(
            "1Password account: give its sign-in address, email or id (see `op account list`)"
                .into(),
        )
    }
}

pub fn reference(vault: &str, title: &str) -> String {
    format!("op://{vault}/{title}/password")
}

/// Stores `words` as a new Password item and returns its `op://` reference (not secret).
pub fn store(account: &str, vault: &str, title: &str, words: &str) -> Result<String, String> {
    check_account(account)?;
    check_name("vault name", vault)?;
    check_name("item title", title)?;
    // BIP39 words are lowercase ASCII separated by single spaces: nothing in them needs JSON escaping.
    if !words.chars().all(|c| c.is_ascii_lowercase() || c == ' ') {
        return Err("share words must be lowercase BIP39 words".into());
    }
    let template = Zeroizing::new(format!(
        r#"{{"title":"{title}","category":"PASSWORD","fields":[{{"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password","value":"{words}"}}]}}"#
    ));
    run(
        &[
            "item",
            "create",
            "--account",
            account,
            "--vault",
            vault,
            "-",
        ],
        &template,
    )?; // its output is dropped
    Ok(reference(vault, title))
}

/// Reads a share back from its `op://` reference. 1Password asks for Touch ID (or its password) here.
pub fn read(account: &str, reference: &str) -> Result<Zeroizing<String>, String> {
    check_account(account)?;
    let ok = reference.starts_with("op://") && reference.chars().all(|c| !c.is_control());
    if !ok {
        return Err("not a 1Password reference (op://vault/item/field)".into());
    }
    let out = run(
        &["read", "--account", account, "--no-newline", reference],
        "",
    )?;
    let text = std::str::from_utf8(&out).map_err(|_| "op returned non-text".to_string())?;
    Ok(Zeroizing::new(text.trim().to_string()))
}

/// A share kept in 1Password, as a recovery sheet names it.
pub struct SheetRef {
    pub x: u8,
    pub reference: String,
    pub account: String,
}

/// The sheet line for a share: `1password:  share 2 op://... account my.1password.com`.
pub fn sheet_line(x: u8, reference: &str, account: &str) -> String {
    format!("{SHEET_PREFIX:<18}share {x} {reference} account {account}")
}

/// Every share a recovery sheet names on `1password:` lines (see `sheet_line`).
pub fn sheet_references(sheet: &str) -> Vec<SheetRef> {
    sheet
        .lines()
        .filter_map(|l| {
            let mut t = l.strip_prefix(SHEET_PREFIX)?.split_whitespace();
            let (Some("share"), Some(x), Some(r), Some("account"), Some(a)) =
                (t.next(), t.next(), t.next(), t.next(), t.next())
            else {
                return None;
            };
            Some(SheetRef {
                x: x.parse().ok()?,
                reference: r.to_string(),
                account: a.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_sheet_lines() {
        assert!(check_name("v", "Private").is_ok());
        for bad in ["", "a\"b", "a/b", "a\nb"] {
            assert!(check_name("v", bad).is_err(), "{bad:?}");
        }
        let line = sheet_line(
            2,
            "op://Personal/epn-share-2-ab/password",
            "my.1password.com",
        );
        let refs = sheet_references(&format!("x\n{line}   (read with `op read`)\n"));
        assert_eq!(refs.len(), 1);
        assert_eq!(
            (
                refs[0].x,
                refs[0].reference.as_str(),
                refs[0].account.as_str()
            ),
            (
                2,
                "op://Personal/epn-share-2-ab/password",
                "my.1password.com"
            )
        );
        // A line without its account is not trusted: restore then asks rather than letting op guess.
        assert!(sheet_references("1password: share 2 op://Personal/x/password\n").is_empty());
        for bad in ["", "my 1password", "a;b"] {
            assert!(check_account(bad).is_err(), "{bad:?}");
        }
        assert!(store("my.1password.com", "Personal", "t", "ABC").is_err()); // refused before op is run
        assert!(read("my.1password.com", "http://x").is_err());
        assert!(read("", "op://Personal/x/password").is_err());
    }
}
