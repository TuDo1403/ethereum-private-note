//! Terminal prompts shared by backup and restore. Every secret is read with echo off and held in
//! `Zeroizing`; the screen (and its scrollback) is cleared after a secret was shown.

use epn_core::bip39::{complete_word, share_from_words};
use std::io::Write;
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

pub fn yes(prompt: &str) -> Result<bool, String> {
    loop {
        match ask(&format!("{prompt} [y/n]: "))?.to_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer y or n."),
        }
    }
}

/// Asks for 1 or 2.
pub fn choose_1_or_2() -> Result<u8, String> {
    loop {
        match ask("1 or 2: ")?.as_str() {
            "1" => return Ok(1),
            "2" => return Ok(2),
            _ => {}
        }
    }
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
