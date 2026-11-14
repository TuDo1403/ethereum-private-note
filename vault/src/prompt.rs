//! Terminal prompts shared by backup and restore. Every secret is read with echo off and held in
//! `Zeroizing`; the screen (and its scrollback) is cleared after a secret was shown.

use console::style;
use dialoguer::{Confirm, Select, theme::ColorfulTheme};
use epn_core::bip39::{complete_word, share_from_words};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::Write;
use std::time::Duration;
use zeroize::Zeroizing;

/// Attempts a person gets at a typed secret before the step gives up.
pub const TRIES: usize = 3;

pub fn ask(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut s = String::new();
    match std::io::stdin().read_line(&mut s) {
        Ok(0) => Err("input closed".into()),
        Ok(_) => Ok(s.trim().to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// Reads from the tty with echo off.
pub fn ask_hidden(prompt: &str) -> Result<Zeroizing<String>, String> {
    rpassword::prompt_password(prompt).map(Zeroizing::new).map_err(|e| e.to_string())
}

pub fn pause(msg: &str) -> Result<(), String> {
    ask(msg).map(|_| ())
}

/// Also clears the scrollback (3J), so a secret does not stay one scroll away.
pub fn clear() {
    print!("\x1b[2J\x1b[3J\x1b[H");
    std::io::stdout().flush().ok();
}

/// y or n, then Enter: a single stray key must not answer a question about secrets.
pub fn yes(prompt: &str) -> Result<bool, String> {
    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .wait_for_newline(true)
        .interact()
        .map_err(|e| e.to_string())
}

/// An arrow-key menu (Enter picks); returns the index of the item chosen.
pub fn choose(prompt: &str, items: &[&str]) -> Result<usize, String> {
    Select::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .items(items)
        .default(0)
        .interact()
        .map_err(|e| e.to_string())
}

/// A step header. Steps that take or show a secret are red, so nobody misses that the screen matters now.
pub fn step(n: usize, total: usize, title: &str, secret: bool) {
    let text = style(format!("{n}/{total} {title}")).bold();
    println!("{}", if secret { text.red() } else { text.cyan() });
}

/// Runs slow work (Argon2id: seconds, with 1 GiB of memory) under a spinner showing the elapsed time,
/// so the wait is visibly alive and nobody presses Ctrl-C thinking it hung.
pub fn working<T>(msg: &str, f: impl FnOnce() -> T) -> T {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::with_template("{spinner} {msg} {elapsed}").expect("valid template"));
    spinner.set_message(msg.to_string());
    spinner.enable_steady_tick(Duration::from_millis(120));
    let out = f();
    let took = spinner.elapsed().as_secs();
    spinner.finish_and_clear();
    println!("{msg}: done in {took} s.");
    out
}

pub fn show_words(title: &str, words: &str) {
    println!("{title}");
    for (i, w) in words.split(' ').enumerate() {
        println!("  {:>2}. {w}", i + 1);
    }
}

/// The paper share's 24 words typed one at a time, so a typo is caught on the spot and not after a full
/// Argon2 run. The first letters are enough (BIP39 words are unique by their first four). Input is hidden.
pub fn enter_paper_share(x: u8) -> Result<Zeroizing<String>, String> {
    let word = |n: usize, hint: &str| -> Result<&'static str, String> {
        loop {
            if let Some(w) = complete_word(&ask_hidden(&format!("paper share {x}, word {n}/24{hint}: "))?) {
                return Ok(w);
            }
            println!("  not a BIP39 word, or too short to be unique: type it again");
        }
    };
    let mut words = (1..=24).map(|n| word(n, " (first letters are enough)")).collect::<Result<Vec<_>, _>>()?;
    loop {
        let joined = Zeroizing::new(words.join(" "));
        let Err(e) = share_from_words(&joined) else { return Ok(joined) };
        // The checksum says some word is wrong but not which one, so the user picks.
        println!("\n{e}");
        let n: usize = ask("Which word number (1-24) do you want to type again? ")?.parse().unwrap_or(0);
        if (1..=24).contains(&n) {
            words[n - 1] = word(n, "")?;
        }
    }
}
