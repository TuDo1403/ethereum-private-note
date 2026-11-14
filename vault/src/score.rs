//! Scores a setup on two axes, Loss (can you still restore after losing shares) and Theft (what the
//! cheapest opening combination costs a thief), and lists warnings that each end with one suggested fix.
//!
//! A combination that opens the backup is exactly a k-subset of the shares (at most C(5,2) = 10), so
//! everything is enumerated. Places are optional input, used only here and never stored or logged; scoring
//! warns and never fails.

use crate::layout::{Layout, ShareKind};

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

/// Every k-subset of `0..n`, in lexicographic order.
pub fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    fn extend(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for i in start..n {
            cur.push(i);
            extend(i + 1, n, k, cur, out);
            cur.pop();
        }
    }
    let mut out = Vec::new();
    extend(0, n, k, &mut Vec::new(), &mut out);
    out
}

fn shares(m: usize) -> String {
    format!("{m} share{}", if m == 1 { "" } else { "s" })
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
    let mut warnings = Vec::new();

    let mut loss_weak = n == k;
    if loss_weak {
        warnings.push("losing any one share locks you out → add a share".to_string());
    }
    if let (Some(places), true) = (places, n > k) {
        let mut seen: Vec<&String> = Vec::new();
        for p in places {
            if !seen.contains(&p) {
                seen.push(p);
            }
        }
        for place in seen {
            let here: Vec<usize> = (0..n).filter(|&i| places[i] == *place).collect();
            if here.len() > n - k {
                loss_weak = true;
                warnings.push(format!(
                    "a fire at {place} leaves {}; you need {k} → keep {} somewhere else",
                    shares(n - here.len()),
                    label(here[0])
                ));
            }
        }
    }
    let loss = match (loss_weak, n - k) {
        (true, _) => Verdict::Weak,
        (false, 1) => Verdict::Ok,
        _ => Verdict::Strong,
    };

    let mut theft_weak = false;
    if let Some(places) = places {
        // One warning per place, naming the first combination (lexicographic) that it holds whole.
        let mut warned: Vec<&String> = Vec::new();
        for c in &combos {
            let place = &places[c[0]];
            if c.iter().all(|&i| places[i] == *place) && !warned.contains(&place) {
                warned.push(place);
                theft_weak = true;
                let names: Vec<&str> = c.iter().map(|&i| label(i)).collect();
                let raise = if k < n {
                    format!(", or use {} of {n}", k + 1)
                } else {
                    String::new()
                };
                warnings.push(format!(
                    "one break-in at {place} opens it: {} → keep {} somewhere else{raise}",
                    names.join(" + "),
                    names[names.len() - 1]
                ));
            }
        }
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
    fn combinations_count() {
        assert_eq!(combinations(4, 2).len(), 6);
        assert_eq!(combinations(5, 3).len(), 10);
        assert_eq!(combinations(3, 2), vec![vec![0, 1], vec![0, 2], vec![1, 2]]);
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
    }

    #[test]
    fn without_places_only_place_free_rules_apply() {
        let s = score(&lay("2of3 pass,key,paper"), None);
        assert_eq!((s.loss, s.theft), (Verdict::Ok, Verdict::Ok));
        assert!(!is_weak(&s));
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
}
