use backup_core::*;
use std::io::Read;

// Restore only. Secrets (share C, passphrase) come from stdin, never from arguments, so none of them
// lands in shell history or `ps`. The record, credential id and device path are public.
const USAGE: &str = "usage:
  printf '%s\\n%s' \"$SHARE_C_WORDS\" \"$PASS\" | recover restore <record-hex> [--cred-id ID [--device PATH]]
stdin line 1 is share C, the rest is the passphrase; leave either empty to omit it. Pass --cred-id to
use the YubiKey. Any two of the three factors restore the seed. Backups are made with `vault`.

v2 records (k-of-n, first byte 02):
  recover restore <record-hex> [--key X=CRED_ID]... [--device PATH]  < factors
--key reads the YubiKey that is share X (PIN and touch). stdin has one factor per line, in any order:
  pass <passphrase>          the passphrase, everything after the first space
  paper <X> <24 words>       the paper share printed as share X
  hw <X> <64 hex digits>     a hardware secret as hex, instead of --key
Any k of the factors restore the seed.";

enum Fail {
    Usage(String),
    Error(String),
}

impl From<String> for Fail {
    fn from(e: String) -> Self {
        Fail::Error(e)
    }
}

fn flag(args: &mut Vec<String>, name: &str) -> Result<Option<String>, Fail> {
    let Some(i) = args.iter().position(|a| a == name) else { return Ok(None) };
    if i + 1 >= args.len() {
        return Err(Fail::Usage(format!("{name} needs a value")));
    }
    let value = args.remove(i + 1);
    args.remove(i);
    Ok(Some(value))
}

fn non_empty(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

// Deliberately never echoes the arguments: a misplaced share C or passphrase would be printed.
fn cmd_restore(mut args: Vec<String>) -> Result<(), Fail> {
    let cred_id = flag(&mut args, "--cred-id")?;
    let device = flag(&mut args, "--device")?;
    let mut keys = Vec::new();
    while let Some(k) = flag(&mut args, "--key")? {
        keys.push(k);
    }
    let [record_hex] = args.as_slice() else {
        return Err(Fail::Usage("restore takes exactly one argument: the record hex (secrets must come from stdin)".into()));
    };
    if unhex(record_hex).is_ok_and(|r| r.first() == Some(&v2::VERSION)) {
        if cred_id.is_some() {
            return Err(Fail::Usage("--cred-id is for v1 records; use --key X=CRED_ID for v2".into()));
        }
        return restore_v2(&unhex(record_hex)?, &keys, device.as_deref());
    }
    if !keys.is_empty() {
        return Err(Fail::Usage("--key is for v2 records; use --cred-id for v1".into()));
    }
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).map_err(|_| Fail::Error("stdin is not UTF-8".into()))?;
    let Some((share_c, pass)) = input.split_once('\n') else {
        return Err(Fail::Usage("stdin must be share C words (or empty), a newline, then the passphrase (or empty)".into()));
    };
    // `echo` appends a newline that is not part of the passphrase; strip exactly one.
    let pass = pass.strip_suffix('\n').unwrap_or(pass);
    let record = unhex(record_hex)?;

    let prf = match &cred_id {
        Some(id) => {
            eprintln!("Enter the YubiKey PIN and touch it.");
            Some(fido::secret(id, device.as_deref())?)
        }
        None => None,
    };
    if non_empty(pass).is_some() {
        eprintln!("Stretching passphrase (Argon2id, 1 GiB; takes a while)...");
    }
    let (words, used) = restore(&record, non_empty(pass), prf.as_ref().map(|p| &p[..]), non_empty(share_c.trim()))?;
    eprintln!("Restored using {used}.");
    println!("{words}");
    Ok(())
}

// One factor per stdin line. Errors name the line number and the kind of factor, never the content: it
// is a secret, and a mistyped word is probably one too.
fn restore_v2(record: &[u8], keys: &[String], device: Option<&str>) -> Result<(), Fail> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).map_err(|_| Fail::Error("stdin is not UTF-8".into()))?;
    let bad = |n: usize, what: &str| Fail::Usage(format!("stdin line {n}: invalid {what}; expected `pass <passphrase>`, `paper <X> <24 words>` or `hw <X> <64 hex>`"));
    let (mut pass, mut hardware, mut paper) = (None, Vec::new(), Vec::new());
    for (i, line) in input.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let n = i + 1;
        let (tag, rest) = line.split_once(' ').ok_or(bad(n, "line"))?;
        match tag {
            "pass" if pass.is_none() => pass = Some(rest), // not trimmed: spaces are part of a passphrase
            "pass" => return Err(bad(n, "second passphrase")),
            "paper" | "hw" => {
                let what = if tag == "paper" { "paper share" } else { "hardware secret" };
                let (x, value) = rest.split_once(' ').ok_or(bad(n, what))?;
                let x: u8 = x.parse().map_err(|_| bad(n, what))?;
                if tag == "paper" {
                    share_c_from_words(value).map_err(|_| bad(n, what))?; // 24 words, checksum right
                    paper.push((x, value));
                } else {
                    hardware.push((x, unhex(value).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or(bad(n, what))?));
                }
            }
            _ => return Err(bad(n, "line")),
        }
    }
    // "pass " with nothing after it means the passphrase is not held, like an empty line 2 in v1.
    let pass = pass.filter(|p| !p.is_empty());
    let mut key_list = Vec::new();
    for k in keys {
        let (x, cred) = k.split_once('=').ok_or(Fail::Usage("--key needs X=CRED_ID".into()))?;
        let x: u8 = x.parse().map_err(|_| Fail::Usage("--key needs X=CRED_ID with X a number".into()))?;
        key_list.push((x, cred));
    }
    // Validate every factor before the slow and interactive steps: the YubiKey PIN and touch, then Argon2.
    let xs: Vec<u8> = hardware.iter().map(|h| h.0).chain(key_list.iter().map(|k| k.0)).collect();
    v2::check_factors(record, pass.is_some(), &xs, &paper)?;
    for (x, cred) in key_list {
        eprintln!("Enter the PIN and touch the YubiKey that is share {x}.");
        hardware.push((x, fido::secret(cred, device)?));
    }
    if pass.is_some() {
        eprintln!("Stretching passphrase (Argon2id; takes a while)...");
    }
    let (words, used) = v2::restore(record, pass, &hardware, &paper)?;
    eprintln!("Restored using shares {used:?}.");
    println!("{words}");
    Ok(())
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = if args.is_empty() { String::new() } else { args.remove(0) };
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
