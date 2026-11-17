//! `vault`: the guided backup and restore. `plan` designs and scores a setup with no secrets; backup walks
//! through the offline half step by step; restore asks which factors you have and walks through each;
//! `op-store` is the online step that puts a 1Password share into 1Password.
//!
//! Secrets (seed, passphrase, paper shares, YubiKey secrets) live in memory only, wrapped in `Zeroizing`
//! where the type allows. That is best effort: copies made by the format crate's helpers are not wiped. The
//! real protection is running this on an offline machine and clearing the screen after each secret is shown.
//!
//! Nothing here is needed to restore: `recover` and SPEC.md stand alone.

mod backup;
mod layout;
mod onepassword;
mod prompt;
mod restore;
mod score;
mod setup;
mod sheet;

use clap::{Parser, Subcommand};
use epn_core::host;
use prompt::{choose, clear};
use std::io::IsTerminal;

/// Guided, offline seed backup and restore (Ethereum Private Note). Without a command, shows a menu.
/// Secrets are only ever typed at prompts, never given as arguments.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
    /// FIDO2 device path, when several keys are plugged in (see `fido2-token -L`)
    #[arg(long, global = true, value_name = "PATH")]
    device: Option<String>,
    /// Continue even though this host is online or has a monitoring agent (keyloggers see everything)
    #[arg(long, global = true)]
    allow_unsafe_host: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make a new backup of a seed (run it offline)
    Backup {
        /// A setup file saved by `vault plan`; without one, the setup is chosen now
        setup: Option<String>,
    },
    /// Design and score a setup with no secrets (any machine); saves it as setup.txt, without places
    Plan,
    /// Restore a seed, or verify a backup without ever showing the seed
    Restore,
    /// Put a 1Password share of a backup into 1Password (online; only that share is typed)
    OpStore {
        /// The backup's recovery-sheet.txt, which names the account and the item
        sheet: String,
    },
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("vault is interactive: run it in a terminal, not through a pipe".into());
    }
    for w in host::harden() {
        eprintln!("warning: {w}");
    }
    let command = match cli.command {
        Some(c) => c,
        None => {
            clear();
            match choose(
                "What do you want to do?",
                &[
                    "Make a new backup of a seed",
                    "Plan a setup (no secrets)",
                    "Restore a seed from a backup",
                ],
            )? {
                0 => Cmd::Backup { setup: None },
                1 => Cmd::Plan,
                _ => Cmd::Restore,
            }
        }
    };
    // `plan` handles no secret and `op-store` types only one 1Password share on a machine that never holds
    // another factor: both are meant to run online. Everything else types factors, so a keylogger would see them.
    if !matches!(command, Cmd::Plan | Cmd::OpStore { .. }) {
        host::require_trusted_host(cli.allow_unsafe_host)?;
    }
    match command {
        Cmd::Backup { setup } => backup::backup(setup, cli.device),
        Cmd::Plan => setup::plan(),
        Cmd::Restore => restore::restore_flow(cli.device),
        Cmd::OpStore { sheet } => backup::op_store(&sheet),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
