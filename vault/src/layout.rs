//! The setup an owner chooses: which shares exist (passphrase, YubiKeys, paper, 1Password), how many are
//! needed (k), and the plan file (`setup.txt`) that carries a setup from `vault plan` to `vault backup`.
//!
//! A setup says nothing about where the shares are kept: places are used only to score a setup while
//! planning and are never stored here or written to the plan file, because a file that says where each
//! share lives is a map for a thief.

use crate::onepassword::{check_account, check_name};
use epn_core::record::Kind;

/// The format allows at most 5 shares (SPEC.md); k is at least 2 so no single share restores the seed.
pub const MAX_SHARES: usize = 5;
const MAX_LABEL: usize = 40;
const PLAN_HEADER: &str = "epn setup v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareKind {
    Passphrase,
    YubiKey,
    Paper,
    /// A paper-kind share stored as a 1Password item, as in `onepassword.rs`.
    OnePassword {
        account: String,
        vault: String,
    },
}

impl ShareKind {
    /// Fixed share order: passphrase, then YubiKeys, then paper and 1Password shares.
    fn rank(&self) -> u8 {
        match self {
            ShareKind::Passphrase => 0,
            ShareKind::YubiKey => 1,
            ShareKind::Paper | ShareKind::OnePassword { .. } => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareSpec {
    pub kind: ShareKind,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    pub k: usize,
    /// `shares[i]` is share x = i + 1.
    pub shares: Vec<ShareSpec>,
}

/// Characters a label must not hold because, printed in a prompt, they could rewrite or disguise the
/// screen: control characters (ESC, CR, newline) and the common Unicode format characters (category Cf)
/// that hide or reorder text (zero width and direction marks, bidi embeddings and isolates, the byte order
/// mark; not every Cf code point, std has no category test). `sheet::parse` skips a share line whose label
/// holds one, so `check_label` refuses the same set: a label accepted while planning must not give a sheet
/// line that restore then ignores.
pub fn hides_text(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// Labels go on the public recovery sheet and inside the plan file's double quotes, so no quotes and
/// nothing `hides_text` names.
pub fn check_label(s: &str) -> Result<(), String> {
    let n = s.chars().count();
    if (1..=MAX_LABEL).contains(&n) && !s.chars().any(|c| c == '"' || hides_text(c)) {
        Ok(())
    } else {
        Err(format!(
            "a label must be 1 to {MAX_LABEL} characters, with no quotes, control or invisible formatting characters"
        ))
    }
}

impl Layout {
    /// Validates (format limits, labels, 1Password names) and puts the shares in the fixed order.
    pub fn new(k: usize, mut shares: Vec<ShareSpec>) -> Result<Layout, String> {
        let n = shares.len();
        if !(2..=MAX_SHARES).contains(&n) {
            return Err(format!("a setup needs 2 to {MAX_SHARES} shares, not {n}"));
        }
        if !(2..=n).contains(&k) {
            return Err(format!("the threshold must be from 2 to {n}, not {k}"));
        }
        if shares
            .iter()
            .filter(|s| s.kind == ShareKind::Passphrase)
            .count()
            > 1
        {
            return Err("a setup can have at most one passphrase share".into());
        }
        for (i, s) in shares.iter().enumerate() {
            check_label(&s.label)?;
            if shares[..i].iter().any(|t| t.label == s.label) {
                return Err(format!("two shares are both labelled \"{}\"", s.label));
            }
            if let ShareKind::OnePassword { account, vault } = &s.kind {
                check_account(account)?;
                check_name("vault name", vault)?;
            }
        }
        shares.sort_by_key(|s| s.kind.rank()); // stable: each group keeps the order chosen
        Ok(Layout { k, shares })
    }

    pub fn n(&self) -> usize {
        self.shares.len()
    }

    pub fn record_kinds(&self) -> Vec<Kind> {
        self.shares
            .iter()
            .map(|s| match s.kind {
                ShareKind::Passphrase => Kind::Passphrase,
                ShareKind::YubiKey => Kind::Hardware,
                ShareKind::Paper | ShareKind::OnePassword { .. } => Kind::Paper,
            })
            .collect()
    }

    /// For example `2 of 4   passphrase · YubiKey A · YubiKey B · paper`.
    pub fn summary(&self) -> String {
        let labels: Vec<&str> = self.shares.iter().map(|s| s.label.as_str()).collect();
        format!("{} of {}   {}", self.k, self.n(), labels.join(" · "))
    }

    pub fn to_plan_text(&self) -> String {
        let mut text = format!("{PLAN_HEADER}\nk {}\n", self.k);
        for (i, s) in self.shares.iter().enumerate() {
            let x = i + 1;
            let label = &s.label;
            match &s.kind {
                ShareKind::Passphrase => text += &format!("share {x} passphrase \"{label}\"\n"),
                ShareKind::YubiKey => text += &format!("share {x} yubikey \"{label}\"\n"),
                ShareKind::Paper => text += &format!("share {x} paper \"{label}\"\n"),
                ShareKind::OnePassword { account, vault } => {
                    text += &format!(
                        "share {x} 1password \"{label}\" account {account} vault \"{vault}\"\n"
                    )
                }
            }
        }
        text
    }

    /// Reads a plan file. The file is untrusted input: the result went through `Layout::new`, and the
    /// share numbers must already be in the fixed order, so the numbers the owner saw while planning are
    /// the ones backup uses.
    pub fn parse_plan(text: &str) -> Result<Layout, String> {
        let mut lines = text
            .lines()
            .enumerate()
            .map(|(i, l)| (i + 1, l))
            .filter(|(_, l)| !l.trim().is_empty());
        let at = |n: usize, e: String| format!("setup.txt line {n}: {e}");

        match lines.next() {
            Some((_, PLAN_HEADER)) => {}
            _ => {
                return Err(format!(
                    "setup.txt: the first line must be \"{PLAN_HEADER}\""
                ));
            }
        }
        let (n, line) = lines
            .next()
            .ok_or("setup.txt: the line \"k <number>\" is missing")?;
        let k = line
            .strip_prefix("k ")
            .and_then(|v| v.parse::<usize>().ok())
            .ok_or_else(|| at(n, "expected \"k <number>\"".into()))?;

        let mut shares = Vec::new();
        for (n, line) in lines {
            let (x, share) = parse_share(line).map_err(|e| at(n, e))?;
            if x != shares.len() + 1 {
                return Err(at(
                    n,
                    format!("expected share {}, found share {x}", shares.len() + 1),
                ));
            }
            shares.push(share);
        }

        let layout = Layout::new(k, shares.clone()).map_err(|e| format!("setup.txt: {e}"))?;
        if layout.shares != shares {
            return Err(
                "setup.txt: shares must be in the fixed order: passphrase, then YubiKeys, then paper and 1Password"
                    .into(),
            );
        }
        Ok(layout)
    }
}

/// `share <x> <kind> "<label>"`, plus ` account <account> vault "<vault>"` for 1Password. Errors never
/// echo the file's text: it is untrusted and could carry escape sequences to the terminal.
fn parse_share(line: &str) -> Result<(usize, ShareSpec), String> {
    let bad = || "expected: share <number> <kind> \"<label>\"".to_string();
    let (x, rest) = line
        .strip_prefix("share ")
        .and_then(|r| r.split_once(' '))
        .ok_or_else(bad)?;
    let x: usize = x.parse().map_err(|_| bad())?;
    let (kind, rest) = rest.split_once(' ').ok_or_else(bad)?;
    let (label, rest) = quoted(rest)?;
    let kind = match kind {
        "passphrase" | "yubikey" | "paper" => {
            if !rest.is_empty() {
                return Err("unexpected text after the label".into());
            }
            match kind {
                "passphrase" => ShareKind::Passphrase,
                "yubikey" => ShareKind::YubiKey,
                _ => ShareKind::Paper,
            }
        }
        "1password" => {
            let needs =
                || "a 1password share needs: account <account> vault \"<vault>\"".to_string();
            let (account, rest) = rest
                .strip_prefix(" account ")
                .and_then(|r| r.split_once(' '))
                .ok_or_else(needs)?;
            let (vault, rest) = quoted(rest.strip_prefix("vault ").ok_or_else(needs)?)?;
            if !rest.is_empty() {
                return Err("unexpected text after the vault".into());
            }
            ShareKind::OnePassword {
                account: account.into(),
                vault: vault.into(),
            }
        }
        _ => {
            return Err(
                "unknown share kind (passphrase, yubikey, paper or 1password expected)".into(),
            );
        }
    };
    Ok((
        x,
        ShareSpec {
            kind,
            label: label.into(),
        },
    ))
}

/// Splits `"text" rest` into (`text`, `rest`). Labels and vault names cannot hold a quote, so the first
/// closing quote ends the text.
fn quoted(s: &str) -> Result<(&str, &str), String> {
    s.strip_prefix('"')
        .and_then(|r| r.split_once('"'))
        .ok_or_else(|| "a quoted name is missing its closing quote".to_string())
}

/// The four presets in spec order, as (k, shares) not yet validated: the 1Password preset's account and
/// vault are empty until the setup screen asks for them, and then `Layout::new` validates.
pub fn presets() -> Vec<(usize, Vec<ShareSpec>)> {
    let s = |kind, label: &str| ShareSpec {
        kind,
        label: label.into(),
    };
    let passphrase = || s(ShareKind::Passphrase, "passphrase");
    vec![
        (
            2,
            vec![
                passphrase(),
                s(ShareKind::YubiKey, "YubiKey"),
                s(ShareKind::Paper, "paper"),
            ],
        ),
        (
            2,
            vec![
                passphrase(),
                s(
                    ShareKind::OnePassword {
                        account: String::new(),
                        vault: String::new(),
                    },
                    "1Password",
                ),
                s(ShareKind::Paper, "paper"),
            ],
        ),
        (
            2,
            vec![
                passphrase(),
                s(ShareKind::YubiKey, "YubiKey A"),
                s(ShareKind::YubiKey, "YubiKey B"),
                s(ShareKind::Paper, "paper"),
            ],
        ),
        (
            3,
            vec![
                passphrase(),
                s(ShareKind::YubiKey, "YubiKey A"),
                s(ShareKind::YubiKey, "YubiKey B"),
                s(ShareKind::Paper, "paper A"),
                s(ShareKind::Paper, "paper B"),
            ],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(kind: ShareKind, l: &str) -> ShareSpec {
        ShareSpec {
            kind,
            label: l.into(),
        }
    }

    #[test]
    fn new_orders_and_validates() {
        let l = Layout::new(
            2,
            vec![
                s(ShareKind::Paper, "paper"),
                s(ShareKind::YubiKey, "YubiKey A"),
                s(ShareKind::Passphrase, "passphrase"),
            ],
        )
        .unwrap();
        assert_eq!(
            l.shares
                .iter()
                .map(|s| s.label.as_str())
                .collect::<Vec<_>>(),
            ["passphrase", "YubiKey A", "paper"]
        );
        assert!(Layout::new(1, l.shares.clone()).is_err()); // k < 2
        assert!(Layout::new(4, l.shares.clone()).is_err()); // k > n
        let six = vec![s(ShareKind::Paper, "p"); 6];
        assert!(Layout::new(2, six).is_err()); // n > 5
        let two_pass = vec![s(ShareKind::Passphrase, "a"), s(ShareKind::Passphrase, "b")];
        assert!(Layout::new(2, two_pass).is_err()); // one passphrase at most
        let dup = vec![s(ShareKind::Paper, "x"), s(ShareKind::Paper, "x")];
        assert!(Layout::new(2, dup).is_err()); // labels unique
    }

    #[test]
    fn presets_match_spec() {
        let p = presets();
        assert_eq!(
            p.iter().map(|(k, s)| (*k, s.len())).collect::<Vec<_>>(),
            [(2, 3), (2, 3), (2, 4), (3, 5)]
        );
        let l = |i: usize| Layout::new(p[i].0, p[i].1.clone()).unwrap();
        assert_eq!(
            l(2).summary(),
            "2 of 4   passphrase · YubiKey A · YubiKey B · paper"
        );
        assert_eq!(
            l(0).record_kinds(),
            [Kind::Passphrase, Kind::Hardware, Kind::Paper]
        );
        assert!(Layout::new(p[1].0, p[1].1.clone()).is_err()); // 1Password account/vault still empty
    }

    fn five() -> Layout {
        Layout::new(
            2,
            vec![
                s(ShareKind::Passphrase, "passphrase"),
                s(ShareKind::YubiKey, "YubiKey A"),
                s(ShareKind::YubiKey, "Tante Hélène's key"),
                s(ShareKind::Paper, "paper"),
                s(
                    ShareKind::OnePassword {
                        account: "my.1password.com".into(),
                        vault: "Private Vault".into(),
                    },
                    "1Password",
                ),
            ],
        )
        .unwrap()
    }

    #[test]
    fn plan_file_round_trips() {
        // includes a 1Password share with a spaced vault and a non-ASCII label
        let l = five();
        let text = l.to_plan_text();
        assert!(text.starts_with("epn setup v1\n"));
        assert_eq!(Layout::parse_plan(&text).unwrap(), l);
    }

    #[test]
    fn plan_file_rejects_bad_input() {
        for bad in [
            "",
            "epn setup v2\nk 2\n",
            "epn setup v1\nk 2\n", // no shares
            "epn setup v1\nk 2\nshare 1 yubikey \"a\nshare 2 paper \"b\"\n", // open quote
            "epn setup v1\nk 2\nshare 2 paper \"a\"\nshare 1 paper \"b\"\n", // out of order
            "epn setup v1\nk 2\nshare 1 laser \"a\"\nshare 2 paper \"b\"\n", // unknown kind
            // valid shares, but paper before YubiKey is not the fixed order
            "epn setup v1\nk 2\nshare 1 paper \"a\"\nshare 2 yubikey \"b\"\n",
            // trailing junk after a quoted label
            "epn setup v1\nk 2\nshare 1 paper \"a\" x\nshare 2 paper \"b\"\n",
            // escape sequences in a kind, after a label, after a vault, in a label
            "epn setup v1\nk 2\nshare 1 \x1b[2J \"a\"\nshare 2 paper \"b\"\n",
            "epn setup v1\nk 2\nshare 1 paper \"a\" \x1b[2J\nshare 2 paper \"b\"\n",
            "epn setup v1\nk 2\nshare 1 paper \"a\"\nshare 2 1password \"b\" account a.b vault \"v\" \x1b]0;x\x07\n",
            "epn setup v1\nk 2\nshare 1 paper \"a\x1b[2J\"\nshare 2 paper \"b\"\n",
        ] {
            let e = Layout::parse_plan(bad).unwrap_err();
            assert!(!e.is_empty(), "{bad:?}");
            // the file's text is never echoed: nothing in an error can rewrite the screen
            assert!(!e.chars().any(hides_text), "{bad:?} gave {e:?}");
        }
        let e = Layout::parse_plan("epn setup v1\nk 2\nshare 1 \x1b[2J \"a\"\n").unwrap_err();
        assert!(e.starts_with("setup.txt line 3: unknown share kind"), "{e}");
        assert!(
            check_label("a\"b").is_err()
                && check_label("a\nb").is_err()
                && check_label("").is_err()
        );
        assert!(check_label(&"x".repeat(41)).is_err() && check_label(&"x".repeat(40)).is_ok());
        // exactly what sheet::parse skips: ESC, CR, a bidi override, a zero width space
        for bad in ["a\x1bb", "a\rb", "a\u{202E}b", "a\u{200B}b", "a\u{FEFF}b"] {
            assert!(check_label(bad).is_err(), "{bad:?}");
        }
    }
}
