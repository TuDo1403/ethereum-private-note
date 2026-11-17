//! Terminal prompts shared by backup and restore. Secrets are held in `Zeroizing`, and the screen (and its
//! scrollback) is cleared after a secret was shown. Words are typed with `pick_word`, which shows the letters
//! while they are typed and erases them when the word is taken; hex secrets and the like use no echo.

use console::{Key, Term, style};
use dialoguer::{Confirm, Select, theme::ColorfulTheme};
use epn_core::bip39::{complete_word, words_to_entropy, words_with_prefix};
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
    spinner.set_style(
        ProgressStyle::with_template("{spinner} {msg} {elapsed}").expect("valid template"),
    );
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

/// The paper share's 24 words, each taken only once the letters name one BIP39 word (see `pick_word`).
pub fn enter_paper_share(x: u8) -> Result<Zeroizing<String>, String> {
    enter_words(&format!("paper share {x}"), 24)
}

/// How one word entry ended.
enum Entry {
    Word(&'static str),
    /// Backspace on an empty entry: the person wants to fix the word before.
    Back,
}

/// One BIP39 word, read key by key (like a hardware wallet's keypad) so a typo is stopped where it is made.
/// A letter no word can follow is refused with a beep, the words still possible are listed, and Enter takes
/// the word only once the letters name exactly one (or an exact word). Enter never fires by itself: a typo
/// can be another real word ("wave" for "wage"), and only seeing the word before it is taken catches that.
/// The letters are on screen while typed (needed to see them) and the line is erased when the word is
/// taken, so no word is left in the scrollback. `console` keeps the terminal raw only around each key.
fn pick_word(term: &Term, label: &str) -> Result<Entry, String> {
    let io = |e: std::io::Error| e.to_string();
    let mut typed = Zeroizing::new(String::new());
    loop {
        let mut out = term;
        term.clear_line().map_err(io)?;
        write!(out, "{label}  {}_", *typed).map_err(io)?;
        if let Some(w) = complete_word(&typed) {
            write!(out, "   -> {} (Enter)", style(w).green()).map_err(io)?;
        } else if !typed.is_empty() {
            let left = words_with_prefix(&typed);
            let shown: Vec<_> = left.iter().take(6).copied().collect();
            write!(out, "   {}", shown.join(" ")).map_err(io)?;
            if left.len() > shown.len() {
                write!(out, " +{}", left.len() - shown.len()).map_err(io)?;
            }
        }
        out.flush().map_err(io)?;
        match term.read_key().map_err(io)? {
            Key::Char(c) if c.is_ascii_alphabetic() => {
                typed.push(c.to_ascii_lowercase());
                if words_with_prefix(&typed).is_empty() {
                    typed.pop();
                    write!(out, "\x07").map_err(io)?;
                }
            }
            Key::Backspace if typed.pop().is_none() => return Ok(Entry::Back),
            Key::Tab => {
                if let Some(w) = complete_word(&typed) {
                    typed.clear();
                    typed.push_str(w);
                }
            }
            Key::Enter => match complete_word(&typed) {
                Some(w) => {
                    term.clear_line().map_err(io)?;
                    return Ok(Entry::Word(w));
                }
                None => write!(out, "\x07").map_err(io)?,
            },
            _ => {}
        }
    }
}

/// Fills `words` up to `n` with `pick_word`; Backspace at the start of a word reopens the previous one.
/// Each word taken leaves only a check mark on its line.
fn pick_into(
    term: &Term,
    what: &str,
    words: &mut Vec<&'static str>,
    n: usize,
) -> Result<(), String> {
    let io = |e: std::io::Error| e.to_string();
    while words.len() < n {
        let i = words.len() + 1;
        match pick_word(term, &format!("{what}, word {i}/{n}"))? {
            Entry::Word(w) => {
                words.push(w);
                term.write_line(&format!("{what}, word {i}/{n}  ok"))
                    .map_err(io)?;
            }
            Entry::Back if words.pop().is_some() => {
                // Past the empty prompt line, and the "ok" line of the word being reopened.
                term.clear_line().map_err(io)?;
                term.move_cursor_up(1).map_err(io)?;
                term.clear_line().map_err(io)?;
            }
            Entry::Back => {}
        }
    }
    Ok(())
}

fn terminal() -> Result<Term, String> {
    let term = Term::stdout();
    if term.is_term() {
        Ok(term)
    } else {
        Err("words are typed on a terminal".into())
    }
}

/// `n` words typed with `pick_word`, joined by single spaces. No checksum: for the generated passphrase.
pub fn pick_words(what: &str, n: usize) -> Result<Zeroizing<String>, String> {
    let term = terminal()?;
    let mut words = Vec::with_capacity(n);
    pick_into(&term, what, &mut words, n)?;
    Ok(Zeroizing::new(words.join(" ")))
}

/// `n` BIP39 words typed with `pick_word`, then the checksum is checked, so a typo is caught on the spot and
/// not after a full Argon2 run. The checksum says some word is wrong but not which one, so the person picks.
/// An empty answer gives up: a paper that cannot be typed correctly must not trap the user here.
pub fn enter_words(what: &str, n: usize) -> Result<Zeroizing<String>, String> {
    let term = terminal()?;
    let mut words = Vec::with_capacity(n);
    pick_into(&term, what, &mut words, n)?;
    loop {
        let joined = Zeroizing::new(words.join(" "));
        let Err(e) = words_to_entropy(&joined).map(Zeroizing::new) else {
            return Ok(joined);
        };
        println!("\n{e}");
        let answer = ask(&format!(
            "Which word number (1-{n}) do you want to type again? (Enter gives up) "
        ))?;
        if answer.is_empty() {
            return Err(format!("{what} not entered"));
        }
        if let Ok(i) = answer.parse::<usize>()
            && (1..=n).contains(&i)
        {
            // Only word i is typed again; Backspace on its empty entry has nothing before it to reopen.
            loop {
                if let Entry::Word(w) = pick_word(&term, &format!("{what}, word {i}/{n}"))? {
                    words[i - 1] = w;
                    break;
                }
            }
        }
    }
}

/// Runs `attempt` until it succeeds, at most `TRIES` times, for a step that needs one YubiKey: each failure
/// (a missed touch, a wrong PIN, the wrong key, a refused id) is shown and the owner asked again. With
/// several keys to read, `plug_only` first asks for that key alone to be plugged in: `fido` refuses to guess
/// between keys, and `--device` would make every key be read at one path.
pub fn with_key<T>(
    key: &str,
    plug_only: bool,
    mut attempt: impl FnMut() -> Result<T, String>,
) -> Result<T, String> {
    for _ in 0..TRIES {
        if plug_only {
            pause(&format!("Plug in only {key}, then press Enter."))?;
        }
        match attempt() {
            Ok(done) => return Ok(done),
            Err(e) if several_keys(&e) => println!(
                "More than one key is plugged in: unplug the other keys, leave only {key}, and try again."
            ),
            Err(e) => println!("{e}"),
        }
    }
    Err(format!("{key} was not read after {TRIES} tries"))
}

/// `fido` refuses to guess between keys; the owner only has to unplug one.
pub fn several_keys(error: &str) -> bool {
    error.starts_with("several FIDO2 keys found")
}

/// `--device` names one path, so two YubiKeys would both be read there: they are plugged in one at a time.
pub fn check_device(device: Option<&str>, keys: usize, whose: &str) -> Result<(), String> {
    if device.is_some() && keys > 1 {
        return Err(format!(
            "--device names one key, but {whose} {keys} YubiKeys: run it without --device, and plug in one key at a time when asked"
        ));
    }
    Ok(())
}
