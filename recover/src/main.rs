use backup_core::*;
use std::io::Read;

// Restore only. Secrets (share C, passphrase) come from stdin, never from arguments, so none of them
// lands in shell history or `ps`. The record, credential id and device path are public.
const USAGE: &str = "usage:
  printf '%s\\n%s' \"$SHARE_C_WORDS\" \"$PASS\" | recover restore <record-hex> [--cred-id ID [--device PATH]]
stdin line 1 is share C, the rest is the passphrase; leave either empty to omit it. Pass --cred-id to
use the YubiKey. Any two of the three factors restore the seed. Backups are made with `vault`.";

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
    let [record_hex] = args.as_slice() else {
        return Err(Fail::Usage("restore takes exactly one argument: the record hex (secrets must come from stdin)".into()));
    };
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
