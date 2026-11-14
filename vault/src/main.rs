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

use clap::{Parser, Subcommand};
use prompt::{choose, clear};
use std::io::IsTerminal;

/// Guided, offline seed backup and restore (Ethereum Private Note). Without a command, shows a menu.
/// Secrets are only ever typed at hidden prompts, never given as arguments.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
    /// FIDO2 device path, when several keys are plugged in (see `fido2-token -L`)
    #[arg(long, global = true, value_name = "PATH")]
    device: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make a new backup of a seed (run it offline)
    Backup,
    /// Restore a seed, or verify a backup without ever showing the seed
    Restore,
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("vault is interactive: run it in a terminal, not through a pipe".into());
    }
    let backup = match cli.command {
        Some(Cmd::Backup) => true,
        Some(Cmd::Restore) => false,
        None => {
            clear();
            choose("What do you want to do?", &["Make a new backup of a seed", "Restore a seed from a backup"])? == 0
        }
    };
    if backup { backup::backup(cli.device) } else { restore::restore_flow(cli.device) }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
