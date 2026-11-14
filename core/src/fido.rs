//! The hardware secret from a YubiKey, with no browser: the key's FIDO2 hmac-secret, driven through libfido2's
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
/// Using the same derivation keeps the hardware factor defined the same way whichever tool asks the key.
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
    let _ = child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes());
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "{tool} failed (wrong PIN, key not touched in time, or wrong credential id?)"
        ));
    }
    String::from_utf8(out.stdout).map_err(|_| format!("{tool} printed non-UTF-8 output"))
}

/// `fido2-token -L` prints one `path: vendor=..., product=...` line per key.
fn device_path(given: Option<&str>) -> Result<String, String> {
    if let Some(d) = given {
        return Ok(d.to_string());
    }
    let listing = run("fido2-token", &["-L"], "")?;
    let paths: Vec<&str> = listing
        .lines()
        .filter_map(|l| l.split_once(": vendor").map(|(p, _)| p))
        .collect();
    match paths.as_slice() {
        [one] => Ok(one.to_string()),
        [] => Err("no FIDO2 key found: plug in the YubiKey".into()),
        _ => Err(format!(
            "several FIDO2 keys found, pick one with --device: {}",
            paths.join(", ")
        )),
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
    parse_cred(&out)
}

/// Non-empty base64 on line `i`, or an error naming the tool.
fn b64_line(lines: &[&str], i: usize, tool: &str) -> Result<Vec<u8>, String> {
    Base64::decode_vec(lines[i])
        .ok()
        .filter(|b| !b.is_empty())
        .ok_or(format!("{tool}: unexpected output (line {})", i + 1))
}

/// `fido2-cred -M` output (fido2-cred(1)): client data hash, rp id, attestation format, authenticator
/// data, credential id, attestation signature, then the attestation certificate when there is one.
/// Checked line by line, so output of another shape is refused instead of a wrong line taken as the id.
fn parse_cred(out: &str) -> Result<String, String> {
    let lines: Vec<&str> = out.lines().collect();
    let tool = "fido2-cred";
    if !(6..=7).contains(&lines.len())
        || lines[0] != client_data_hash()
        || lines[1] != RP_ID
        || lines[2].is_empty()
    {
        return Err(format!(
            "{tool}: unexpected output (not a credential for {RP_ID})"
        ));
    }
    for i in [3, 4, 5].into_iter().chain((lines.len() == 7).then_some(6)) {
        b64_line(&lines, i, tool)?;
    }
    Ok(lines[4].to_string())
}

/// `fido2-assert -G` output for one non-resident assertion without `-b` (fido2-assert(1)): exactly
/// client data hash, rp id, authenticator data, signature, hmac-secret. The strict shape matters: a
/// one-line output would otherwise make the echoed client data hash (32 zero bytes) look like a secret.
fn parse_assert(out: &str) -> Result<[u8; 32], String> {
    let lines: Vec<&str> = out.lines().collect();
    let tool = "fido2-assert";
    if lines.len() != 5 || lines[0] != client_data_hash() || lines[1] != RP_ID {
        return Err(format!(
            "{tool}: unexpected output (expected one assertion for {RP_ID} with hmac-secret)"
        ));
    }
    b64_line(&lines, 2, tool)?;
    b64_line(&lines, 3, tool)?;
    let secret = <[u8; 32]>::try_from(b64_line(&lines, 4, tool)?).map_err(|_| {
        format!("{tool} returned no 32-byte hmac-secret (credential made without hmac-secret?)")
    })?;
    // A real hmac-secret output is an HMAC-SHA-256; all zeros means something else was parsed.
    if secret == [0; 32] {
        return Err(format!(
            "{tool} returned an all-zero hmac-secret; refusing it"
        ));
    }
    Ok(secret)
}

/// The id is pasted into the tool's line-based input, so it must be plain base64 (no newline smuggling).
/// Callers check it early: before a PIN is asked for, and at the start of a backup.
pub fn check_cred_id(cred_id: &str) -> Result<(), String> {
    Base64::decode_vec(cred_id)
        .map(drop)
        .map_err(|_| "credential id is not valid base64".to_string())
}

/// `fido2-token -L -k` output: one `<index>: <credential id> <display name> <user id> <type> <protection>`
/// line per credential (`%02u: %s %s %s %s %s %s` in libfido2's tools/token.c; fido2-token(1) does not
/// document it). Only the id is taken; anything of another shape (including the tool's own
/// `<skipped: ...>` lines) is an error, so a credential is never silently missed.
fn parse_credentials(out: &str) -> Result<Vec<String>, String> {
    out.lines()
        .map(|line| {
            let id = line
                .split_once(": ")
                .filter(|(index, _)| !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .filter(|id| check_cred_id(id).is_ok())
                .ok_or("fido2-token: unexpected credential listing")?;
            Ok(id.to_string())
        })
        .collect()
}

/// The credential ids the key holds for rpId `localhost`: PIN required, no touch. Backup uses it to prove
/// that two YubiKey shares are on different physical keys. Prints nothing itself.
pub fn credentials(device: Option<&str>) -> Result<Vec<String>, String> {
    let dev = device_path(device)?;
    parse_credentials(&run("fido2-token", &["-L", "-k", RP_ID, &dev], "")?)
}

/// The key's 32-byte hmac-secret for this credential: PIN and touch required.
pub fn secret(cred_id: &str, device: Option<&str>) -> Result<[u8; 32], String> {
    check_cred_id(cred_id)?;
    let dev = device_path(device)?;
    let input = format!(
        "{}\n{RP_ID}\n{cred_id}\n{}\n",
        client_data_hash(),
        Base64::encode_string(&salt())
    );
    // -v: user verification (PIN). Required, not optional: CTAP2 hmac-secret keeps separate secrets for
    // assertions with and without UV, so dropping -v would silently give a different secret.
    let out = run("fido2-assert", &["-G", "-h", "-v", "-p", &dev], &input)?;
    parse_assert(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(b: &[u8]) -> String {
        Base64::encode_string(b)
    }

    fn assert_out(lines: &[&str]) -> String {
        lines.iter().map(|l| format!("{l}\n")).collect()
    }

    #[test]
    fn assertion_output_is_parsed_strictly() {
        let (hash, auth, sig, secret) = (
            client_data_hash(),
            b64(&[1; 37]),
            b64(&[2; 70]),
            b64(&[7; 32]),
        );
        let good = [hash.as_str(), RP_ID, &auth, &sig, &secret];
        assert_eq!(parse_assert(&assert_out(&good)).unwrap(), [7; 32]);
        // The audit case: one line, the client data hash (32 zero bytes), must not become the hardware secret.
        assert!(parse_assert(&assert_out(&[&hash])).is_err());
        assert!(parse_assert("").is_err());
        // Wrong line count, wrong hash, wrong rp id, missing pieces, wrong secret length, all-zero secret.
        assert!(parse_assert(&assert_out(&good[..4])).is_err());
        assert!(parse_assert(&assert_out(&[&good[..], &[secret.as_str()]].concat())).is_err());
        let zero = b64(&[0; 32]);
        let wrong_secret = b64(&[7; 31]);
        let other_hash = b64(&[9; 32]);
        for bad in [
            [other_hash.as_str(), RP_ID, &auth, &sig, &secret],
            [&hash, "example.com", &auth, &sig, &secret],
            [&hash, RP_ID, "", &sig, &secret],
            [&hash, RP_ID, &auth, "not base64!", &secret],
            [&hash, RP_ID, &auth, &sig, &wrong_secret],
            [&hash, RP_ID, &auth, &sig, &zero],
        ] {
            assert!(parse_assert(&assert_out(&bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn credential_listing_is_parsed() {
        // fido2-token -L -k prints "%02u: %s %s %s %s %s %s" per credential: index, credential id, display
        // name, user id, type, protection (libfido2 tools/token.c, read from the 1.17 binary's format strings).
        let out = "00: Zm9vYmFy backup AQID es256 uvopt\n01: YmF6 backup BAUG es256 uvopt\n";
        assert_eq!(parse_credentials(out).unwrap(), ["Zm9vYmFy", "YmF6"]);
        assert_eq!(parse_credentials("").unwrap(), Vec::<String>::new());
        assert!(parse_credentials("00: not-base64! x y z w\n").is_err());
        // Another shape is an error, not skipped: a missing index, a non-numeric index, no id, tool's own
        // "<skipped: ...>" marker.
        for bad in [
            "Zm9vYmFy backup AQID es256 uvopt\n",
            "ab: Zm9vYmFy backup\n",
            "00:\n",
            "00: \n",
            "00: <skipped: bad cbor>\n",
        ] {
            assert!(parse_credentials(bad).is_err(), "{bad:?}");
        }
        // One bad line spoils the whole listing.
        assert!(parse_credentials("00: Zm9vYmFy a b c d\n01: !! a b c d\n").is_err());
    }

    #[test]
    fn credential_output_is_parsed_strictly() {
        let (hash, auth, id, sig, cert) = (
            client_data_hash(),
            b64(&[1; 37]),
            b64(&[3; 48]),
            b64(&[2; 70]),
            b64(&[4; 300]),
        );
        let good = [hash.as_str(), RP_ID, "packed", &auth, &id, &sig, &cert];
        assert_eq!(parse_cred(&assert_out(&good)).unwrap(), id);
        assert_eq!(
            parse_cred(&assert_out(&good[..6])).unwrap(),
            id,
            "no certificate"
        );
        assert!(parse_cred(&assert_out(&good[..5])).is_err());
        assert!(parse_cred(&assert_out(&[&hash])).is_err());
        assert!(
            parse_cred(&assert_out(&[
                hash.as_str(),
                "example.com",
                "packed",
                &auth,
                &id,
                &sig
            ]))
            .is_err()
        );
        assert!(
            parse_cred(&assert_out(&[
                hash.as_str(),
                RP_ID,
                "packed",
                &auth,
                "",
                &sig
            ]))
            .is_err()
        );
        assert!(parse_cred(&assert_out(&[hash.as_str(), RP_ID, "", &auth, &id, &sig])).is_err());
    }
}
