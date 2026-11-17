//! Restore only, and deliberately small: it is the tool you need in an emergency. Secrets (passphrase,
//! paper shares, hardware secrets) come from stdin, never from arguments, so none of them lands in `ps`
//! or shell history. The record, credential ids and device path are public.

use epn_core::{bip39::share_from_words, fido, host, record, unhex};
use std::io::Read;

const USAGE: &str = "usage:
  recover restore <record-hex> [--key X=CRED_ID[@PATH]]... [--device PATH] [--allow-unsafe-host]  < factors
It refuses to run while a network interface is up or a monitoring agent is installed, unless
--allow-unsafe-host is given: a keylogger sees every factor typed here.
Run it alone and type the factors on stdin, then Ctrl-D; never put a factor inside a command line (shell
history keeps it). --key reads the YubiKey that is share X (PIN and touch). With two or more YubiKeys
plugged in, give each its own device as --key X=CRED_ID@PATH (find paths with `fido2-token -L`);
without @PATH a key uses --device, else the only key found. stdin has one factor per
line, in any order, blank lines ignored:
  pass <passphrase>          the passphrase, everything after the first space, not trimmed
  paper <X> <24 words>       the paper share printed as share X
  hw <X> <64 hex digits>     a hardware secret as hex, instead of --key
Any k of the factors restore the seed. The guided `vault restore` (words typed one at a time) is the normal way;
backups are made with `vault`.";

enum Fail {
    Usage(String),
    Error(String),
}

impl From<String> for Fail {
    fn from(e: String) -> Self {
        Fail::Error(e)
    }
}

/// Removes `name value` from `args` and returns the value.
fn flag(args: &mut Vec<String>, name: &str) -> Result<Option<String>, Fail> {
    let Some(i) = args.iter().position(|a| a == name) else {
        return Ok(None);
    };
    if i + 1 >= args.len() {
        return Err(Fail::Usage(format!("{name} needs a value")));
    }
    let value = args.remove(i + 1);
    args.remove(i);
    Ok(Some(value))
}

/// The factors typed on stdin, one per line. Errors name the line number and the kind of factor, never
/// the content: it is a secret, and a mistyped word is probably one too.
#[derive(Default)]
struct Factors<'a> {
    pass: Option<&'a str>,
    hardware: Vec<(u8, [u8; 32])>,
    paper: Vec<(u8, &'a str)>,
}

fn parse_factors(input: &str) -> Result<Factors<'_>, Fail> {
    let bad = |n: usize, what: &str| {
        Fail::Usage(format!(
            "stdin line {n}: invalid {what}; expected `pass <passphrase>`, `paper <X> <24 words>` or `hw <X> <64 hex>`"
        ))
    };
    let mut f = Factors::default();
    for (i, line) in input
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        let n = i + 1;
        let (tag, rest) = line.split_once(' ').ok_or(bad(n, "line"))?;
        match tag {
            "pass" if f.pass.is_none() => f.pass = Some(rest), // not trimmed: spaces are part of a passphrase
            "pass" => return Err(bad(n, "second passphrase")),
            "paper" | "hw" => {
                let what = if tag == "paper" {
                    "paper share"
                } else {
                    "hardware secret"
                };
                let (x, value) = rest.split_once(' ').ok_or(bad(n, what))?;
                let x: u8 = x.parse().map_err(|_| bad(n, what))?;
                if tag == "paper" {
                    share_from_words(value).map_err(|_| bad(n, what))?; // 24 words, checksum right
                    f.paper.push((x, value));
                } else {
                    f.hardware.push((
                        x,
                        unhex(value)
                            .ok()
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                            .ok_or(bad(n, what))?,
                    ));
                }
            }
            _ => return Err(bad(n, "line")),
        }
    }
    // "pass " with nothing after it means the passphrase is not held.
    f.pass = f.pass.filter(|p| !p.is_empty());
    Ok(f)
}

// Deliberately never echoes the arguments: a misplaced secret would be printed.
fn cmd_restore(mut args: Vec<String>) -> Result<(), Fail> {
    let device = flag(&mut args, "--device")?;
    let allow_unsafe_host = args
        .iter()
        .position(|a| a == "--allow-unsafe-host")
        .map(|i| args.remove(i))
        .is_some();
    let mut keys = Vec::new();
    while let Some(k) = flag(&mut args, "--key")? {
        let bad = || Fail::Usage("--key needs X=CRED_ID[@PATH] with X a number".into());
        let (x, rest) = k.split_once('=').ok_or_else(bad)?;
        let x: u8 = x.parse().map_err(|_| bad())?;
        // Base64 has no '@', so the first one starts the device path. An empty path is a typo, not "auto-detect".
        let (cred, path) = match rest.split_once('@') {
            Some((_, "")) | Some(("", _)) => return Err(bad()),
            Some((cred, path)) => (cred, Some(path)),
            None => (rest, None),
        };
        keys.push((x, cred.to_string(), path.map(str::to_string)));
    }
    let [record_hex] = args.as_slice() else {
        return Err(Fail::Usage(
            "restore takes exactly one argument: the record hex (secrets must come from stdin)"
                .into(),
        ));
    };
    let record = unhex(record_hex)?;
    // Before stdin is read, so a refused run costs the user nothing they typed.
    host::require_trusted_host(allow_unsafe_host)?;
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|_| Fail::Error("stdin is not UTF-8".into()))?;
    let mut f = parse_factors(&input)?;

    // Validate every factor before the slow and interactive steps: the YubiKey PIN and touch, then Argon2.
    let xs: Vec<u8> = f
        .hardware
        .iter()
        .map(|h| h.0)
        .chain(keys.iter().map(|k| k.0))
        .collect();
    record::check_factors(&record, f.pass.is_some(), &xs, &f.paper)?;
    for (_, cred, _) in &keys {
        fido::check_cred_id(cred)?;
    }
    for (x, cred, path) in keys {
        eprintln!("Enter the PIN and touch the YubiKey that is share {x}.");
        // The key's own path, else --device, else auto-detect.
        let dev = path.as_deref().or(device.as_deref());
        f.hardware.push((x, fido::secret(&cred, dev)?));
    }
    if f.pass.is_some() {
        eprintln!("Stretching passphrase (Argon2id; takes a while)...");
    }
    let (words, used) = record::restore(&record, f.pass, &f.hardware, &f.paper)?;
    eprintln!("Restored using shares {used:?}.");
    println!("{words}");
    Ok(())
}

fn main() {
    for w in host::harden() {
        eprintln!("warning: {w}");
    }
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = if args.is_empty() {
        String::new()
    } else {
        args.remove(0)
    };
    let result = match cmd.as_str() {
        "restore" => cmd_restore(args),
        _ => Err(Fail::Usage("expected the subcommand: restore".into())),
    };
    match result {
        Ok(()) => {}
        Err(Fail::Usage(m)) => {
            eprintln!("error: {m}\n{USAGE}");
            std::process::exit(2);
        }
        Err(Fail::Error(m)) => {
            eprintln!("error: {m}");
            std::process::exit(1);
        }
    }
}
