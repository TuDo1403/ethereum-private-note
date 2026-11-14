//! Factor B from a YubiKey, with no browser: the key's FIDO2 hmac-secret, driven through libfido2's
//! command-line tools (`fido2-token`, `fido2-cred`, `fido2-assert`). The PIN prompt and the touch happen
//! inside those tools on the tty, so this process never sees the PIN. The only secret it handles is the
//! 32-byte hmac-secret output, and only in memory.
//!
//! The credential is resident (the key remembers it) but is always asserted by its credential id, taken
//! from the recovery sheet: that avoids "which of several credentials for localhost?" and still works
//! if the sheet is lost, because the id can be listed from the key with its PIN (`fido2-token -L -k`).

use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::{Command, Stdio};

const RP_ID: &str = "localhost";

/// The hmac-secret salt a browser derives for WebAuthn PRF input "bk1": SHA-256("WebAuthn PRF" || 0x00 || "bk1").
/// Using the same derivation keeps factor B defined the same way whichever tool asks the key.
fn salt() -> [u8; 32] {
    Sha256::digest(b"WebAuthn PRF\0bk1").into()
}

/// The client data hash only matters when an assertion is verified, which nothing here does.
fn client_data_hash() -> String {
    Base64::encode_string(&[0u8; 32])
}

fn run(tool: &str, args: &[&str], input: &str) -> Result<String, String> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // the tool's prompts ("touch your key") must reach the user
        .spawn()
        .map_err(|e| format!("cannot run {tool}: {e} (install libfido2: `brew install libfido2` or `apt install fido2-tools`)"))?;
    // A write error just means the tool exited early; its exit status below is the real answer.
    let _ = child.stdin.take().expect("piped stdin").write_all(input.as_bytes());
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("{tool} failed (wrong PIN, key not touched in time, or wrong credential id?)"));
    }
    String::from_utf8(out.stdout).map_err(|_| format!("{tool} printed non-UTF-8 output"))
}

/// `fido2-token -L` prints one `path: vendor=..., product=...` line per key.
fn device_path(given: Option<&str>) -> Result<String, String> {
    if let Some(d) = given {
        return Ok(d.to_string());
    }
    let listing = run("fido2-token", &["-L"], "")?;
    let paths: Vec<&str> = listing.lines().filter_map(|l| l.split_once(": vendor").map(|(p, _)| p)).collect();
    match paths.as_slice() {
        [one] => Ok(one.to_string()),
        [] => Err("no FIDO2 key found: plug in the YubiKey".into()),
        _ => Err(format!("several FIDO2 keys found, pick one with --device: {}", paths.join(", "))),
    }
}

/// Creates a resident credential with hmac-secret for rpId `localhost` and returns its credential id
/// (base64). The id is not secret and is useless without the key, but backup and restore need it.
pub fn enroll(device: Option<&str>) -> Result<String, String> {
    let dev = device_path(device)?;
    // Random user id, so a new credential never overwrites an existing one for the same rpId.
    let user_id = Base64::encode_string(&crate::os_random(16));
    let input = format!("{}\n{RP_ID}\nbackup\n{user_id}\n", client_data_hash());
    let out = run("fido2-cred", &["-M", "-h", "-r", "-v", &dev], &input)?;
    // Output: client data hash, rp id, format, authenticator data, credential id, signature, ...
    out.lines().nth(4).map(str::to_string).ok_or_else(|| "fido2-cred printed no credential id".to_string())
}

/// The key's 32-byte hmac-secret for this credential: PIN and touch required.
pub fn secret(cred_id: &str, device: Option<&str>) -> Result<[u8; 32], String> {
    // The id is pasted into the tool's line-based input, so it must be plain base64 (no newline smuggling).
    Base64::decode_vec(cred_id).map_err(|_| "credential id is not valid base64".to_string())?;
    let dev = device_path(device)?;
    let input = format!("{}\n{RP_ID}\n{cred_id}\n{}\n", client_data_hash(), Base64::encode_string(&salt()));
    let out = run("fido2-assert", &["-G", "-h", "-v", "-p", &dev], &input)?;
    // Output for a non-resident assertion: hash, rp id, auth data, signature, then the hmac secret.
    let last = out.lines().last().ok_or_else(|| "fido2-assert printed nothing".to_string())?;
    Base64::decode_vec(last)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| "fido2-assert returned no 32-byte hmac-secret (credential made without hmac-secret?)".to_string())
}
