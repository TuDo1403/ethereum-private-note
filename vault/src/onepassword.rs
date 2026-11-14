//! Share 2 kept in 1Password instead of on a YubiKey: a paper share (24 words) stored as a 1Password item
//! and read back with `op read`, which the 1Password app unlocks with Touch ID. The record format does not
//! change: to the record this is just a paper share that happens to live in a password manager.
//!
//! The words reach `op` through stdin (a JSON item template) and come back through a pipe, so they are
//! never on a command line (visible in `ps`) or in a file. Needs the 1Password app with "Integrate with
//! 1Password CLI" switched on (Settings > Developer), and the `op` command installed.

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
        .map_err(|e| format!("cannot run op: {e} (install the 1Password CLI and turn on its app integration)"))?;
    // A write error just means op exited early; its exit status below is the real answer.
    let _ = child.stdin.take().expect("piped stdin").write_all(input.as_bytes());
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let stdout = Zeroizing::new(out.stdout);
    if !out.status.success() {
        return Err("op failed (1Password locked, Touch ID cancelled, wrong vault or item?)".into());
    }
    Ok(stdout)
}

/// Vault and item names go into the JSON template and the `op://` reference, so only plain characters
/// are allowed: no quotes (JSON), no slash (reference separator), no control characters.
pub fn check_name(what: &str, s: &str) -> Result<(), String> {
    let ok = !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || " -_.".contains(c));
    if ok { Ok(()) } else { Err(format!("{what} may only hold letters, digits, space, '-', '_' and '.'")) }
}

pub fn reference(vault: &str, title: &str) -> String {
    format!("op://{vault}/{title}/password")
}

/// Stores `words` as a new Password item and returns its `op://` reference (not secret).
pub fn store(vault: &str, title: &str, words: &str) -> Result<String, String> {
    check_name("vault name", vault)?;
    check_name("item title", title)?;
    // BIP39 words are lowercase ASCII separated by single spaces: nothing in them needs JSON escaping.
    if !words.chars().all(|c| c.is_ascii_lowercase() || c == ' ') {
        return Err("share words must be lowercase BIP39 words".into());
    }
    let template = Zeroizing::new(format!(
        r#"{{"title":"{title}","category":"PASSWORD","fields":[{{"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password","value":"{words}"}}]}}"#
    ));
    run(&["item", "create", "--vault", vault, "-"], &template)?; // its output (an item summary) is dropped
    Ok(reference(vault, title))
}

/// Reads a share back from its `op://` reference. 1Password asks for Touch ID (or its password) here.
pub fn read(reference: &str) -> Result<Zeroizing<String>, String> {
    let ok = reference.starts_with("op://") && reference.chars().all(|c| !c.is_control());
    if !ok {
        return Err("not a 1Password reference (op://vault/item/field)".into());
    }
    let out = run(&["read", "--no-newline", reference], "")?;
    let text = std::str::from_utf8(&out).map_err(|_| "op returned non-text".to_string())?;
    Ok(Zeroizing::new(text.trim().to_string()))
}

/// The (share, reference) pairs a recovery sheet names, from lines `1password: share 2 op://...`.
pub fn sheet_references(sheet: &str) -> Vec<(u8, String)> {
    sheet
        .lines()
        .filter_map(|l| {
            let mut t = l.strip_prefix(SHEET_PREFIX)?.split_whitespace();
            let (Some("share"), Some(x), Some(r)) = (t.next(), t.next(), t.next()) else { return None };
            Some((x.parse().ok()?, r.to_string()))
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
        let sheet = "x\n1password:       share 2 op://Private/epn-share-2-ab/password   (Touch ID)\n";
        assert_eq!(sheet_references(sheet), vec![(2, "op://Private/epn-share-2-ab/password".to_string())]);
        assert!(store("Private", "t", "ABC").is_err()); // refused before op is run
        assert!(read("http://x").is_err());
    }
}
