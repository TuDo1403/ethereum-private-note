//! `vault`: the guided backup and restore. Backup walks through the offline half step by step; restore asks
//! which factors you have and walks through each.
//!
//! Secrets (seed, passphrase, paper share, YubiKey secret) live in memory only, wrapped in `Zeroizing`
//! where the type allows. That is best effort: copies made by the format crate's helpers are not wiped. The
//! real protection is running this on an offline machine and clearing the screen after each secret is shown.
//!
//! Nothing here is needed to restore: `recover` and SPEC.md stand alone.

mod backup;
mod onepassword;
mod prompt;
mod restore;

use prompt::{choose_1_or_2, clear};
use std::io::IsTerminal;

fn run() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let device = match args.iter().position(|a| a == "--device") {
        Some(i) if i + 1 < args.len() => {
            args.remove(i);
            Some(args.remove(i))
        }
        Some(_) => return Err("--device needs a value".into()),
        None => None,
    };
    let backup = match args.as_slice() {
        [] => None,
        [m] if m == "backup" => Some(true),
        [m] if m == "restore" => Some(false),
        _ => return Err("usage: vault [backup|restore] [--device PATH]".into()),
    };
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("vault is interactive: run it in a terminal, not through a pipe".into());
    }
    let backup = match backup {
        Some(b) => b,
        None => {
            clear();
            println!("What do you want to do?\n  1. make a new backup of a seed\n  2. restore a seed from a backup\n");
            choose_1_or_2()? == 1
        }
    };
    if backup { backup::backup(device) } else { restore::restore_flow(device) }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
