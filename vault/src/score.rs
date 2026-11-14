//! Scores a setup on two axes, Loss (can you still restore after losing shares) and Theft (what the
//! cheapest opening combination costs a thief), and lists warnings that each end with one suggested fix.
//!
//! A combination that opens the backup is exactly a k-subset of the shares (at most C(5,2) = 10), so
//! everything is enumerated. Places are optional input, used only here and never stored or logged; scoring
//! warns and never fails. One 1Password account counts like one place: a fire or a breach takes all of its
//! shares at once.

use crate::layout::{Layout, ShareKind, combinations};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Weak,
    Ok,
    Strong,
}

#[derive(Debug)]
pub struct Score {
    pub loss: Verdict,
    pub theft: Verdict,
    pub warnings: Vec<String>,
    /// Every combination that opens the backup, as 0-based share indexes.
    pub combos: Vec<Vec<usize>>,
}

fn shares(m: usize) -> String {
    format!("{m} share{}", if m == 1 { "" } else { "s" })
}

/// Shares that one event takes together: those kept in one place (compared case aside) and those in one
/// 1Password account. The account is in the setup, so those groups exist with places unknown too.
struct Group<'a> {
    name: &'a str,
    account: bool,
    shares: Vec<usize>,
}

fn groups<'a>(layout: &'a Layout, places: Option<&'a [String]>) -> Vec<Group<'a>> {
    let mut out: Vec<Group> = Vec::new();
    let mut add = |name: &'a str, account: bool, i: usize| {
        let same = |g: &Group| g.account == account && g.name.to_lowercase() == name.to_lowercase();
        match out.iter_mut().find(|g| same(g)) {
            Some(g) => g.shares.push(i),
            None => out.push(Group {
                name,
                account,
                shares: vec![i],
            }),
        }
    };
    for (i, s) in layout.shares.iter().enumerate() {
        if let Some(places) = places {
            add(&places[i], false, i);
        }
        if let ShareKind::OnePassword { account, .. } = &s.kind {
            add(account, true, i);
        }
    }
    out
}

/// `places[i]` is the place of share i; `None` means places are unknown (a backup run from `setup.txt`),
/// so only the rules that need no places apply.
pub fn score(layout: &Layout, places: Option<&[String]>) -> Score {
    let (n, k) = (layout.n(), layout.k);
    let label = |i: usize| layout.shares[i].label.as_str();
    let combos = combinations(n, k);
    // A list of the wrong length cannot be matched to shares: a caller bug, caught in tests; in a release
    // build it counts as unknown rather than index out of range.
    if let Some(p) = places {
        debug_assert_eq!(p.len(), n, "one place per share");
    }
    let places = places.filter(|p| p.len() == n);
    let groups = groups(layout, places);
    let mut warnings = Vec::new();

    let mut loss_weak = n == k;
    if loss_weak {
        warnings.push("losing any one share locks you out → add a share".to_string());
    }
    if n > k {
        for g in groups.iter().filter(|g| g.shares.len() > n - k) {
            loss_weak = true;
            let (event, fix) = if g.account {
                (
                    format!("losing the 1Password account {}", g.name),
                    "in another account",
                )
            } else {
                (format!("a fire at {}", g.name), "somewhere else")
            };
            warnings.push(format!(
                "{event} leaves {}; you need {k} → keep {} {fix}",
                shares(n - g.shares.len()),
                label(g.shares[0])
            ));
        }
    }
    let loss = match (loss_weak, n - k) {
        (true, _) => Verdict::Weak,
        (false, 1) => Verdict::Ok,
        _ => Verdict::Strong,
    };

    let mut theft_weak = false;
    for g in &groups {
        // A higher k helps only while the group holds no more than k shares.
        let raise = if k + 1 < n && g.shares.len() <= k {
            format!(", or use {} of {n}", k + 1)
        } else {
            String::new()
        };
        // The first combination (lexicographic) that the group holds whole.
        let Some(c) = combos
            .iter()
            .find(|c| c.iter().all(|i| g.shares.contains(i)))
        else {
            continue;
        };
        theft_weak = true;
        let names: Vec<&str> = c.iter().map(|&i| label(i)).collect();
        let (event, fix) = if g.account {
            (
                format!("one breach of the 1Password account {}", g.name),
                "in another account",
            )
        } else {
            (format!("one break-in at {}", g.name), "somewhere else")
        };
        warnings.push(format!(
            "{event} opens it: {} → keep {} {fix}{raise}",
            names.join(" + "),
            names[names.len() - 1]
        ));
    }
    let needs_yubikey = |c: &Vec<usize>| {
        c.iter()
            .any(|&i| layout.shares[i].kind == ShareKind::YubiKey)
    };
    // Without a YubiKey a thief needs only papers, or papers plus a 1Password account: not "strong".
    let theft = match (theft_weak, combos.iter().all(needs_yubikey)) {
        (true, _) => Verdict::Weak,
        (false, true) => Verdict::Strong,
        (false, false) => Verdict::Ok,
    };

    Score {
        loss,
        theft,
        warnings,
        combos,
    }
}

pub fn is_weak(s: &Score) -> bool {
    s.loss == Verdict::Weak || s.theft == Verdict::Weak
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::ShareSpec;

    /// `lay("2of4 pass,key,key,paper")`: tokens are pass, key, paper, op. Labels follow the presets.
    fn lay(spec: &str) -> Layout {
        let (head, kinds) = spec.split_once(' ').unwrap();
        let k = head.split_once("of").unwrap().0.parse().unwrap();
        let kinds: Vec<&str> = kinds.split(',').collect();
        let mut seen = std::collections::HashMap::new();
        let shares = kinds
            .iter()
            .map(|&t| {
                let (kind, base) = match t {
                    "pass" => (ShareKind::Passphrase, "passphrase"),
                    "key" => (ShareKind::YubiKey, "YubiKey"),
                    "paper" => (ShareKind::Paper, "paper"),
                    "op" => (
                        ShareKind::OnePassword {
                            account: "my.1password.com".into(),
                            vault: "Private".into(),
                        },
                        "1Password",
                    ),
                    _ => panic!("unknown token {t}"),
                };
                let nth = seen.entry(t).or_insert(0u8);
                let total = kinds.iter().filter(|&&u| u == t).count();
                let label = if total == 1 {
                    base.to_string()
                } else {
                    format!("{base} {}", (b'A' + *nth) as char)
                };
                *nth += 1;
                ShareSpec { kind, label }
            })
            .collect();
        Layout::new(k, shares).unwrap()
    }

    fn places<const N: usize>(p: [&str; N]) -> Vec<String> {
        p.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn loss_rules() {
        // n - k = 0 -> Weak; 1 -> Ok; >= 2 -> Strong (places all distinct)
        assert_eq!(score(&lay("2of2 pass,key"), None).loss, Verdict::Weak);
        assert_eq!(score(&lay("2of3 pass,key,paper"), None).loss, Verdict::Ok);
        assert_eq!(
            score(&lay("2of4 pass,key,key,paper"), None).loss,
            Verdict::Strong
        );
        // a place holding more than n - k shares -> Weak, warning names the place
        let s = score(
            &lay("2of4 pass,key,key,paper"),
            Some(&places(["home", "home", "home", "office"])),
        );
        assert_eq!(s.loss, Verdict::Weak);
        assert!(
            s.warnings
                .iter()
                .any(|w| w.contains("a fire at home leaves 1 share;"))
        );
        // two shares left reads "shares"
        let s = score(
            &lay("3of5 pass,key,key,paper,paper"),
            Some(&places(["home", "home", "home", "a", "b"])),
        );
        assert!(
            s.warnings
                .iter()
                .any(|w| w.contains("a fire at home leaves 2 shares; you need 3"))
        );
        // one 1Password account is lost together, wherever the places are: 3 of 4 cannot lose two shares
        for p in [Some(places(["a", "b", "c", "d"])), None] {
            let s = score(&lay("3of4 pass,op,op,paper"), p.as_deref());
            assert_eq!(s.loss, Verdict::Weak);
            assert!(
                s.warnings.iter().any(|w| {
                    w.starts_with(
                        "losing the 1Password account my.1password.com leaves 2 shares; you need 3",
                    ) && w.ends_with("→ keep 1Password A in another account")
                }),
                "{:?}",
                s.warnings
            );
        }
    }

    #[test]
    fn theft_rules() {
        // every k-subset needs a YubiKey -> Strong
        assert_eq!(
            score(&lay("3of4 key,key,key,paper"), None).theft,
            Verdict::Strong
        );
        // some k-subset is papers only, spread over places -> Ok
        assert_eq!(
            score(&lay("2of3 pass,key,paper"), Some(&places(["a", "b", "c"]))).theft,
            Verdict::Ok
        );
        // one place holds a whole k-subset -> Weak, warning names place and labels
        let s = score(
            &lay("2of4 pass,key,key,paper"),
            Some(&places(["home", "home", "office", "parents"])),
        );
        assert_eq!(s.theft, Verdict::Weak);
        assert!(s.warnings.iter().any(|w| {
            w.contains("one break-in at home opens it: passphrase + YubiKey A")
                && w.ends_with("→ keep YubiKey A somewhere else, or use 3 of 4")
        }));
        // raising k offers nothing when the place holds more than k shares
        let s = score(
            &lay("2of4 paper,paper,paper,paper"),
            Some(&places(["h"; 4])),
        );
        assert!(
            s.warnings.iter().all(|w| !w.contains("or use")),
            "{:?}",
            s.warnings
        );
        // places are compared case aside
        let s = score(
            &lay("2of4 pass,key,key,paper"),
            Some(&places(["Home", "home", "office", "parents"])),
        );
        assert_eq!(s.theft, Verdict::Weak);
    }

    #[test]
    fn one_warning_per_place_and_account_combos_are_not_strong() {
        // home holds 3 of 3 shares: every combo is inside it, but only one theft warning
        let s = score(
            &lay("2of3 pass,op,paper"),
            Some(&places(["home", "home", "home"])),
        );
        assert_eq!(
            s.warnings.iter().filter(|w| w.contains("break-in")).count(),
            1
        );
        // a 1Password share with no YubiKey anywhere is not "needs a YubiKey"
        assert_eq!(score(&lay("2of3 pass,op,paper"), None).theft, Verdict::Ok);
        // 2 of 2 has nothing to raise k to
        let s = score(&lay("2of2 pass,key"), Some(&places(["a", "a"])));
        assert!(
            s.warnings
                .iter()
                .any(|w| w.ends_with("→ keep YubiKey somewhere else"))
        );
        assert!(is_weak(&s));
    }

    #[test]
    fn one_account_holding_a_combination_is_weak() {
        // 1Password A and B in one account: one breach opens it, wherever the places are, and with none.
        let same = lay("2of3 op,op,paper");
        for p in [Some(places(["a", "b", "c"])), None] {
            let s = score(&same, p.as_deref());
            assert_eq!(s.theft, Verdict::Weak);
            assert!(s.warnings.iter().any(|w| {
                w == "one breach of the 1Password account my.1password.com opens it: 1Password A + 1Password B → keep 1Password B in another account"
            }), "{:?}", s.warnings);
        }
        // the account is compared case aside, and warned about once
        let mut shares = same.shares.clone();
        shares[1].kind = ShareKind::OnePassword {
            account: "My.1Password.com".into(),
            vault: "Private".into(),
        };
        let s = score(&Layout::new(2, shares.clone()).unwrap(), None);
        assert_eq!(s.theft, Verdict::Weak);
        // 3 of 3 needs the paper too: no combination lies in the account
        assert_eq!(score(&lay("3of3 op,op,paper"), None).theft, Verdict::Ok);
        // different accounts: not weak by this rule
        shares[1].kind = ShareKind::OnePassword {
            account: "other.1password.com".into(),
            vault: "Private".into(),
        };
        let s = score(
            &Layout::new(2, shares).unwrap(),
            Some(&places(["a", "b", "c"])),
        );
        assert_eq!(s.theft, Verdict::Ok);
        assert!(!s.warnings.iter().any(|w| w.contains("breach")));
        // 3 of 4 with three shares in one account
        let s = score(&lay("3of4 op,op,op,paper"), None);
        assert_eq!(
            s.warnings.iter().filter(|w| w.contains("breach")).count(),
            1
        );
    }
}
