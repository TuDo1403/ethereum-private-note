//! Drives the interactive `vault` through a pty with `expect` (skipped if it is not installed), with fake
//! `fido2-cred` / `fido2-assert` on PATH standing in for the YubiKey. One backup, then a verify-only
//! restore from the papers it printed.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const SEED: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
// One letter off and still checksum-valid: exactly the typo a single entry would back up silently.
const TYPO: &str = "legal winner thank year wage sausage worth useful legal winner thank yellow";

const SCRIPT: &str = r#"
set timeout 300
proc fail {msg} { puts stderr "\nFAIL: $msg"; exit 1 }
# rpassword prints its prompt before it turns echo off; a person types later than that, a script must
# wait, or the pty echoes the "hidden" seed into the transcript that the test checks for leaks.
proc secret {s} { sleep 0.3; send "$s\r" }
proc type_words {words} {
    foreach w $words { expect -re {share C word [0-9]+/24[^:]*: }; send "$w\r" }
}
proc words_of {block} {
    set out {}
    foreach {all w} [regexp -all -inline {[0-9]+\. ([a-z]+)} $block] { lappend out $w }
    return $out
}

spawn $env(VAULT) backup --device /dev/fake
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
expect -re {saved in \./(backup-[0-9]+)/} { set dir $expect_out(1,string) }
if {![file isdirectory $dir]} { fail "output folder not made before the start" }
expect "offline and ready."; send "\r"
expect "make a new one: "; send "\r"
expect "credential id: Zm9vYmFy"

# Seed twice: a checksum-valid typo in the second entry is caught.
expect "Type your seed words"; secret $env(SEED)
expect "Type them again"; secret $env(TYPO)
expect "not the same seed"
expect "Type your seed words"; secret $env(SEED)
expect "Type them again"; secret $env(SEED)
expect -re {Seed fingerprint: ([0-9a-f]{8})} { set fp $expect_out(1,string) }

expect -re {passphrase:\r\n((?: +[0-9]+\. [a-z]+\r\n){7})} { set pass [join [words_of $expect_out(1,string)] " "] }
expect "once it is written down"; send "\r"
expect "passphrase: "; send "$pass\r"

# The public files exist before share C is shown.
expect "Saved two PUBLIC files"
if {![file exists $dir/record.hex] || ![file exists $dir/recovery-sheet.txt]} { fail "files not saved before share C" }
expect -re {share C:\r\n((?: +[0-9]+\. [a-z]+\r\n){24})} { set sharec [words_of $expect_out(1,string)] }
expect "type all 24 words back"; send "\r"

# Full re-entry: a different (valid) share is refused and share C is shown again.
type_words [concat [lrepeat 23 abandon] art]
expect "is not the share C shown"
expect "type it again."; send "\r"
type_words $sharec
expect "6/6 Backup made"
expect "publish <rpc-url>"
expect eof

# Verify only: the papers open the record, the fingerprint is shown, the seed is not.
spawn $env(VAULT) restore
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
expect "1 or 2: "; send "2\r"
expect "record.hex: "; send "$dir/record.hex\r"
expect -ex {passphrase [y/n]: }; send "y\r"
expect -ex {YubiKey and its PIN [y/n]: }; send "n\r"
expect -ex {share C (24 words) [y/n]: }; send "y\r"
type_words $sharec
expect "exactly as written (hidden): "; send "$pass\r"
expect -re {Seed fingerprint: ([0-9a-f]{8})} {
    if {$expect_out(1,string) ne $fp} { fail "verify-only fingerprint $expect_out(1,string) is not $fp" }
}
expect eof
puts "\nDIR=$dir FP=$fp"
"#;

fn tool(dir: &std::path::Path, name: &str, body: &str) {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn backup_then_verify_only_restore() {
    if Command::new("expect").arg("-v").output().is_err() {
        eprintln!("skipped: `expect` is not installed");
        return;
    }
    let work = std::env::temp_dir().join(format!("epn-vault-guided-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let bin = work.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    // Both echo the client data hash and rp id they were sent, as libfido2 does (see core/src/fido.rs).
    tool(&bin, "fido2-cred", "read h; read rp; read user; read uid; printf '%s\\n' \"$h\" \"$rp\" packed AQID Zm9vYmFy AQID AQID");
    let secret = format!("{}AQE=", "AQEB".repeat(10)); // 32 bytes of 0x01
    tool(&bin, "fido2-assert", &format!("read h; read rp; read id; read salt; printf '%s\\n' \"$h\" \"$rp\" AQID AQID {secret}"));
    let script = work.join("guided.exp");
    std::fs::write(&script, SCRIPT).unwrap();

    let out = Command::new("expect")
        .arg(&script)
        .current_dir(&work)
        .env("PATH", format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default()))
        .env("VAULT", env!("CARGO_BIN_EXE_vault"))
        .env("SEED", SEED)
        .env("TYPO", TYPO)
        .output()
        .unwrap();
    let transcript = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(out.status.success(), "{transcript}\n{}", String::from_utf8_lossy(&out.stderr));

    let fp = epn_core::seed_fingerprint(&epn_core::words_to_entropy(SEED).unwrap());
    let dir = work.join(transcript.rsplit_once("DIR=").unwrap().1.split_whitespace().next().unwrap());
    assert!(transcript.contains(&format!("FP={fp}")), "fingerprint shown is not the seed's");
    // The seed is never on screen (it is typed hidden), in backup or in verify-only restore.
    assert!(!transcript.contains("sausage"), "seed shown");
    // No restore command that puts secrets on a command line; the test step points to verify only.
    assert!(!transcript.contains("SHARE_C_WORDS") && !transcript.contains("cast send"), "{transcript}");
    assert!(transcript.contains("verify only"));

    let record_hex = std::fs::read_to_string(dir.join("record.hex")).unwrap();
    let record = epn_core::unhex(&record_hex).unwrap();
    let sheet = std::fs::read_to_string(dir.join("recovery-sheet.txt")).unwrap();
    for want in [
        "cast code <address>".to_string(),
        format!("record id:        {}", epn_core::record_id(&record)),
        format!("seed fingerprint: {fp}"),
        format!("record:           {}", record_hex.trim()),
        "credential:       Zm9vYmFy".to_string(),
        "read -rs".to_string(),
        "vault restore".to_string(),
    ] {
        assert!(sheet.contains(&want), "sheet lacks {want:?}:\n{sheet}");
    }
    assert!(!sheet.contains("SHARE_C_WORDS"));
    assert!(!dir.join(".write-test").exists());
    std::fs::remove_dir_all(&work).unwrap();
}
