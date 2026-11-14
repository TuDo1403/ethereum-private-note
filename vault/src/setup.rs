//! The setup screens shared by `vault plan` and `vault backup`: choose a setup (a preset or custom shares
//! and threshold), labels, the 1Password account and vault of each 1Password share, where each share will
//! be kept, then a review screen that scores it (score.rs) and lists every combination that opens it.
//!
//! Places live only in memory, here and in the private "where things are" list `plan` shows once: a file
//! that says where each share lives is a map for a thief, so they never reach setup.txt, the sheet or a log.
//! A weak setup is never refused, but taking it needs the owner to type `yes` past the warning naming it.

use crate::layout::{Layout, MAX_SHARES, ShareKind, ShareSpec, check_label, presets};
use crate::onepassword::{check_account, check_name};
use crate::prompt::{self, TRIES, ask, clear, pause, yes};
use crate::score::{Verdict, is_weak, score};
use std::io::Write;

/// Presets or custom, then labels, 1Password account/vault, places, review. Loops until accepted.
/// Returns the setup and `places[i]`, the place of share i.
pub fn choose() -> Result<(Layout, Vec<String>), String> {
    loop {
        let layout = pick_setup()?;
        loop {
            let places = ask_places(&layout)?;
            if review(&layout, Some(&places))? {
                return Ok((layout, places));
            }
            if prompt::choose("What do you want to change?", &["the places", "the setup"])? == 1 {
                break;
            }
        }
    }
}

/// The share kinds as the owner sees them, with their default label stem.
const KINDS: [(&str, ShareKind); 3] = [
    ("passphrase", ShareKind::Passphrase),
    ("YubiKey", ShareKind::YubiKey),
    ("paper", ShareKind::Paper),
];

fn one_password() -> ShareKind {
    // account and vault are asked for once the shares are known (`onepassword_details`)
    ShareKind::OnePassword {
        account: String::new(),
        vault: String::new(),
    }
}

fn pick_setup() -> Result<Layout, String> {
    let mut presets = presets();
    let notes = ["(today's setup)", "(today's 1Password setup)", "", ""];
    let mut items: Vec<String> = presets
        .iter()
        .zip(notes)
        .map(|((k, shares), note)| {
            let labels: Vec<&str> = shares.iter().map(|s| s.label.as_str()).collect();
            let line = format!(
                "{k} of {}   {:<44} {note}",
                shares.len(),
                labels.join(" · ")
            );
            line.trim_end().to_string()
        })
        .collect();
    items.push("Custom   pick each share, then the threshold".into());
    let items: Vec<&str> = items.iter().map(String::as_str).collect();
    clear();
    let i = prompt::choose("How should this backup be split?", &items)?;
    let (k, shares) = if i < presets.len() {
        presets.swap_remove(i)
    } else {
        custom()?
    };
    let shares = onepassword_details(rename(shares)?)?;
    Layout::new(k, shares)
}

/// Shares one at a time (passphrase at most once, 2 to 5 shares), then k from 2..=n, with default labels
/// "YubiKey A", "YubiKey B", ... when a kind is used more than once.
fn custom() -> Result<(usize, Vec<ShareSpec>), String> {
    let mut kinds: Vec<(&str, ShareKind)> = Vec::new();
    while kinds.len() < MAX_SHARES {
        let mut offer: Vec<(&str, ShareKind)> = KINDS
            .iter()
            .filter(|(_, k)| *k != ShareKind::Passphrase || !kinds.iter().any(|(_, h)| h == k))
            .cloned()
            .collect();
        offer.push(("1Password", one_password()));
        let mut items: Vec<String> = offer.iter().map(|(name, _)| name.to_string()).collect();
        if kinds.len() >= 2 {
            items.push("done: choose how many shares it takes".into());
        }
        if !kinds.is_empty() {
            let so_far: Vec<&str> = kinds.iter().map(|(name, _)| *name).collect();
            println!("Shares so far: {}", so_far.join(", "));
        }
        let items: Vec<&str> = items.iter().map(String::as_str).collect();
        let i = prompt::choose(
            &format!("Add share {} (at most {MAX_SHARES})", kinds.len() + 1),
            &items,
        )?;
        match offer.get(i) {
            Some(kind) => kinds.push(kind.clone()),
            None => break,
        }
    }
    let n = kinds.len();
    let ks: Vec<String> = (2..=n).map(|k| format!("{k} of {n}")).collect();
    let ks: Vec<&str> = ks.iter().map(String::as_str).collect();
    let k = 2 + prompt::choose("How many shares should it take to restore the seed?", &ks)?;

    let shares = kinds
        .iter()
        .enumerate()
        .map(|(i, (name, kind))| {
            let same = |(m, _): &&(&str, ShareKind)| m == name;
            let label = if kinds.iter().filter(same).count() == 1 {
                name.to_string()
            } else {
                let nth = kinds[..i].iter().filter(same).count() as u8;
                format!("{name} {}", (b'A' + nth) as char)
            };
            ShareSpec {
                kind: kind.clone(),
                label,
            }
        })
        .collect();
    Ok((k, shares))
}

/// Labels are printed on the public recovery sheet, so the owner is told to keep places out of them; the
/// review screen also warns if one names a place.
fn rename(mut shares: Vec<ShareSpec>) -> Result<Vec<ShareSpec>, String> {
    let labels: Vec<&str> = shares.iter().map(|s| s.label.as_str()).collect();
    println!("\nLabels: {}", labels.join(" · "));
    println!(
        "Labels name the shares on the recovery sheet, which is PUBLIC: never put a place in a label."
    );
    if !yes("Rename any of them?")? {
        return Ok(shares);
    }
    for i in 0..shares.len() {
        loop {
            let new = ask(&format!(
                "New label for \"{}\" (Enter keeps it): ",
                shares[i].label
            ))?;
            if new.is_empty() {
                break;
            }
            let taken = shares
                .iter()
                .enumerate()
                .any(|(j, s)| j != i && s.label == new);
            match check_label(&new) {
                Err(e) => println!("{e}"),
                Ok(()) if taken => println!("another share is already labelled \"{new}\""),
                Ok(()) => {
                    shares[i].label = new;
                    break;
                }
            }
        }
    }
    Ok(shares)
}

/// A value checked as it is typed, so a typo is caught on the spot and not by `Layout::new` afterwards.
fn ask_checked(prompt: &str, check: impl Fn(&str) -> Result<(), String>) -> Result<String, String> {
    for _ in 0..TRIES {
        let v = ask(prompt)?;
        match check(&v) {
            Ok(()) => return Ok(v),
            Err(e) => println!("{e}"),
        }
    }
    Err("no valid answer given".into())
}

fn onepassword_details(mut shares: Vec<ShareSpec>) -> Result<Vec<ShareSpec>, String> {
    if !shares
        .iter()
        .any(|s| matches!(s.kind, ShareKind::OnePassword { .. }))
    {
        return Ok(shares);
    }
    // Both asked for explicitly: with several accounts signed in, a default would let `op` choose, and a
    // work account (whose admins can reach it, and which ends with the job) must never be chosen silently.
    println!(
        "\nUse a PERSONAL 1Password account, never a work one. `op account list` shows yours."
    );
    for s in shares.iter_mut() {
        if let ShareKind::OnePassword { account, vault } = &mut s.kind {
            *account = ask_checked(
                &format!(
                    "1Password account for \"{}\" (sign-in address or email, e.g. my.1password.com): ",
                    s.label
                ),
                check_account,
            )?;
            *vault = ask_checked(
                &format!(
                    "Vault in that account (`op vault list --account {account}` lists them): "
                ),
                |v| check_name("vault name", v),
            )?;
        }
    }
    println!(
        "Keep the other shares OUT of these 1Password accounts: a breach of one account must never be enough."
    );
    println!(
        "1Password needs the network, so the backup does not touch it: each 1Password share is shown as 24"
    );
    println!(
        "words for a TEMPORARY paper, and `vault op-store` puts it into 1Password later, on your online machine."
    );
    Ok(shares)
}

/// For each share, a place from those named so far or a new one. Returns one place per share, in share order.
fn ask_places(layout: &Layout) -> Result<Vec<String>, String> {
    clear();
    println!("Setup: {}\n", layout.summary());
    println!(
        "Where will each share be kept? Places only score this setup: they are never saved anywhere.\n"
    );
    let mut named: Vec<String> = Vec::new();
    let mut places = Vec::with_capacity(layout.n());
    for s in &layout.shares {
        let mut items: Vec<&str> = named.iter().map(String::as_str).collect();
        items.push("+ new place");
        let i = prompt::choose(&format!("Where will {} be kept?", s.label), &items)?;
        let place = match named.get(i) {
            Some(p) => p.clone(),
            None => loop {
                let p = ask("New place (for example home safe, office, parents): ")?;
                if !p.is_empty() {
                    named.push(p.clone());
                    break p;
                }
            },
        };
        places.push(place);
    }
    Ok(places)
}

fn mark(v: Verdict) -> &'static str {
    match v {
        Verdict::Weak => "⚠ weak  ",
        Verdict::Ok => "✓ ok    ",
        Verdict::Strong => "✓ strong",
    }
}

/// Whether `label` holds the words of `place` in a row, as whole words and case aside: place "home" is in
/// "home key" but not in "homeless", place "a" not in "paper" (it is in "paper A").
fn names_place(label: &str, place: &str) -> bool {
    let words = |s: &str| -> Vec<String> {
        s.split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(str::to_lowercase)
            .collect()
    };
    let (label, place) = (words(label), words(place));
    !place.is_empty() && label.windows(place.len()).any(|w| w == place.as_slice())
}

/// The review screen: summary, Loss/Theft lines, warnings, every combination; Ok(true) = accepted.
/// Without places (a backup from setup.txt) only the rules that need none apply.
pub fn review(layout: &Layout, places: Option<&[String]>) -> Result<bool, String> {
    let s = score(layout, places);
    let mut warnings = s.warnings.clone();
    // Labels are public: a place in one would put it on the sheet.
    for sh in &layout.shares {
        if let Some(p) = places
            .into_iter()
            .flatten()
            .find(|p| names_place(&sh.label, p))
        {
            warnings.push(format!(
                "the label \"{}\" names the place {p}, and labels go on the public recovery sheet → rename it",
                sh.label
            ));
        }
    }
    let weak = is_weak(&s) || warnings.len() > s.warnings.len();

    println!("\nSetup: {}\n", layout.summary());
    let spare = layout.n() - layout.k;
    let loss = match s.loss {
        Verdict::Weak => "you can be locked out (see below)".to_string(),
        _ if spare == 1 => "you can lose any 1 share".to_string(),
        _ => format!("you can lose any {spare} shares"),
    };
    let theft = match s.theft {
        Verdict::Weak => "one break-in can open it (see below)",
        Verdict::Ok => "some combinations need no YubiKey: keep their shares in different places",
        Verdict::Strong => "every combination needs a YubiKey and its PIN",
    };
    println!("Loss    {}  {loss}", mark(s.loss));
    println!("Theft   {}  {theft}", mark(s.theft));
    for w in &warnings {
        let (what, fix) = w.split_once(" → ").unwrap_or((w, ""));
        println!("\n⚠ {what}");
        if !fix.is_empty() {
            println!("  → {fix}");
        }
    }

    println!("\nAll {} combinations that open it:", s.combos.len());
    let names: Vec<String> = s
        .combos
        .iter()
        .map(|c| {
            let labels: Vec<&str> = c.iter().map(|&i| layout.shares[i].label.as_str()).collect();
            labels.join(" + ")
        })
        .collect();
    let width = names.iter().map(|n| n.chars().count()).max().unwrap_or(0) + 4;
    for row in names.chunks((96 / width).clamp(1, 3)) {
        let line: String = row.iter().map(|n| format!("{n:<width$}")).collect();
        println!("  {}", line.trim_end());
    }

    // Without places the setup came from setup.txt and cannot be changed here: declining stops the backup.
    let from_file = places.is_none();
    if weak {
        let prompt = if from_file {
            "\nThis setup is weak. To use it anyway, type yes; press Enter to stop (change it with `vault plan`): "
        } else {
            "\nThis setup is weak. To use it anyway, type yes; press Enter to change it: "
        };
        return Ok(ask(prompt)? == "yes");
    }
    let prompt = if from_file {
        "\nPress Enter to use this setup, or type back to stop (change it with `vault plan`): "
    } else {
        "\nPress Enter to use this setup, or type back to change it: "
    };
    // Only Enter accepts: a typed "no" must not take the setup.
    loop {
        match ask(prompt)?.as_str() {
            "" => return Ok(true),
            "back" => return Ok(false),
            _ => println!("Press Enter, or type back."),
        }
    }
}

/// `vault plan`: choose, save `setup.txt` (or `setup-<n>.txt` if taken), show the private where-things-are list
/// (label -> place) once, clear the screen on Enter.
pub fn plan() -> Result<(), String> {
    clear();
    println!(
        "Plan a backup setup. No secrets are asked for, so this may run on any machine, online too."
    );
    let (layout, places) = choose()?;
    let path = save_plan(&layout.to_plan_text())?;
    clear();
    println!(
        "Saved {path} (no places, no secrets). Make the backup offline with: vault backup {path}\n"
    );
    println!(
        "Where things are. PRIVATE and saved nowhere: write it down where a thief would not look, or remember it."
    );
    let width = layout
        .shares
        .iter()
        .map(|s| s.label.chars().count())
        .max()
        .unwrap_or(0);
    for (s, p) in layout.shares.iter().zip(&places) {
        println!("  {:<width$}  {p}", s.label);
    }
    pause("\nPress Enter to clear the screen.")?;
    clear();
    Ok(())
}

/// setup.txt in the current folder, or setup-2.txt, setup-3.txt, ... when taken: an earlier plan is
/// never overwritten.
fn save_plan(text: &str) -> Result<String, String> {
    let mut n = 1;
    loop {
        let path = if n == 1 {
            "setup.txt".to_string()
        } else {
            format!("setup-{n}.txt")
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                return f
                    .write_all(text.as_bytes())
                    .map(|_| path.clone())
                    .map_err(|e| format!("cannot write {path}: {e}"));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => n += 1,
            Err(e) => return Err(format!("cannot write {path}: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::names_place;

    #[test]
    fn a_place_is_found_in_a_label_by_whole_words() {
        assert!(names_place("Home key", "home"));
        assert!(names_place("key in the home safe", "Home Safe"));
        assert!(names_place("paper A", "a"));
        assert!(!names_place("paper", "a"));
        assert!(!names_place("homeless key", "home"));
        assert!(!names_place("home key", "home safe"));
        assert!(!names_place("paper", "--"));
    }
}
