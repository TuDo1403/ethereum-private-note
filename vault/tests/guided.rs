//! Drives the interactive `vault` through a pty with `expect` (skipped if it is not installed), with fake
//! `fido2-cred` / `fido2-assert` on PATH standing in for the YubiKey. One backup, then a verify-only
//! restore from the papers it printed.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const SEED: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
// One letter off and still checksum-valid: exactly the typo a single entry would back up silently.
const TYPO: &str = "legal winner thank year wage sausage worth useful legal winner thank yellow";

const HELPERS: &str = r#"
set timeout 300
proc fail {msg} { puts stderr "\nFAIL: $msg"; exit 1 }
# rpassword prints its prompt before it turns echo off; a person types later than that, a script must
# wait, or the pty echoes the "hidden" seed into the transcript that the test checks for leaks.
proc secret {s} { sleep 0.3; send "$s\r" }
# Menus and y/n questions (dialoguer) read keys in raw mode once drawn: wait for the prompt, pause like a
# person, then press keys. `pick n` moves down n items and presses Enter.
proc pick {prompt n} { expect -ex $prompt; sleep 0.3; send [string repeat "\033\[B" $n]; send "\r" }
proc answer {prompt key} { expect -ex $prompt; expect -ex {(y/n)}; sleep 0.3; send "$key\r" }
proc type_words {words} {
    foreach w $words { expect -re {paper share [0-9]+, word [0-9]+/24[^:]*: }; send "$w\r" }
}
proc words_of {block} {
    set out {}
    foreach {all w} [regexp -all -inline {[0-9]+\. ([a-z]+)} $block] { lappend out $w }
    return $out
}
"#;

const SCRIPT: &str = r#"
spawn $env(VAULT) backup --device /dev/fake
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
expect -re {saved in \./(backup-[0-9]+)/} { set dir $expect_out(1,string) }
if {![file isdirectory $dir]} { fail "output folder not made before the start" }
expect "offline and ready."; send "\r"
pick "Which second factor?" 0
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

# The public files exist before the paper share is shown.
expect "Saved two PUBLIC files"
if {![file exists $dir/record.hex] || ![file exists $dir/recovery-sheet.txt]} { fail "files not saved before the paper share" }
expect -re {paper share \(this is share 3\):\r\n((?: +[0-9]+\. [a-z]+\r\n){24})} { set sharec [words_of $expect_out(1,string)] }
expect "type all 24 words back"; send "\r"

# Full re-entry: a different (valid) share is refused and the paper share is shown again.
type_words [concat [lrepeat 23 abandon] art]
expect "is not the share shown"
expect "type it again."; send "\r"
type_words $sharec
expect "6/6 Backup made"
expect "publish <rpc-url>"
expect eof

# Verify only: the papers open the record, the fingerprint is shown, the seed is not.
spawn $env(VAULT) restore
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
pick "What should this run do?" 0
expect "record.hex: "; send "$dir/record.hex\r"
answer "share 1: passphrase" y
answer "share 2: YubiKey and its PIN" n
answer "share 3: paper share (24 words)" y
expect "exactly as written (hidden): "; send "$pass\r"
type_words $sharec
expect -re {Seed fingerprint: ([0-9a-f]{8})} {
    if {$expect_out(1,string) ne $fp} { fail "verify-only fingerprint $expect_out(1,string) is not $fp" }
}
expect eof
puts "\nDIR=$dir FP=$fp"
"#;

/// Share 2 in 1Password: an offline backup that never runs `op` and shows share 2 for a temporary paper,
/// then `vault op-store` (twice: the second run must find the item, not duplicate it), then a verify-only
/// restore from the 1Password share and the paper share (no passphrase, so no Argon2 in the restore).
const SCRIPT_1PASSWORD: &str = r#"
spawn $env(VAULT) backup
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
expect -re {saved in \./(backup-[0-9]+)/} { set dir $expect_out(1,string) }
expect "offline and ready."; send "\r"
pick "Which second factor?" 1
expect "PERSONAL 1Password account"
expect "e.g. my.1password.com): "; send "my.1password.com\r"
expect "lists them): "; send "Personal\r"
expect "OUT of this 1Password account"
expect "Type your seed words"; secret $env(SEED)
expect "Type them again"; secret $env(SEED)
expect -re {Seed fingerprint: ([0-9a-f]{8})} { set fp $expect_out(1,string) }
expect -re {passphrase:\r\n((?: +[0-9]+\. [a-z]+\r\n){7})} { set pass [join [words_of $expect_out(1,string)] " "] }
expect "once it is written down"; send "\r"
expect "passphrase: "; send "$pass\r"
expect "Saved two PUBLIC files"
expect -re {paper share \(this is share 3\):\r\n((?: +[0-9]+\. [a-z]+\r\n){24})} { set sharec [words_of $expect_out(1,string)] }
expect "type all 24 words back"; send "\r"
type_words $sharec
expect -re {share 2 for 1Password \(TEMPORARY paper\):\r\n((?: +[0-9]+\. [a-z]+\r\n){24})} { set shareb [words_of $expect_out(1,string)] }
expect "type all 24 words back"; send "\r"
type_words $shareb
expect "6/6 Backup made"
expect "vault op-store $dir/recovery-sheet.txt"
expect eof
if {[file exists "$env(WORK)/op-argv.log"]} { fail "the offline backup ran op" }

spawn $env(VAULT) op-store $dir/recovery-sheet.txt
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
type_words $shareb
expect "Again"
type_words $shareb
# The item does not exist, so the fake `op read` fails: that is not proof of absence, a person confirms.
answer "NO item" y
expect -re {Share 2 is in 1Password as (op://[^ ]+) } { set ref $expect_out(1,string) }
expect "destroy the temporary share-2 paper"
expect eof

spawn $env(VAULT) op-store $dir/recovery-sheet.txt
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
type_words $shareb
expect "Again"
type_words $shareb
expect "already in 1Password"
expect eof

spawn $env(VAULT) restore
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
pick "What should this run do?" 0
expect "record.hex: "; send "$dir/record.hex\r"
answer "share 1: passphrase" n
answer "share 2: 1Password item (Touch ID)" y
answer "share 3: paper share (24 words)" y
answer "it asks for Touch ID?" y
type_words $sharec
expect -re {Seed fingerprint: ([0-9a-f]{8})} {
    if {$expect_out(1,string) ne $fp} { fail "verify-only fingerprint $expect_out(1,string) is not $fp" }
}
expect eof

# A failing `op read` (locked, Touch ID cancelled) must not end the restore: it falls back to the paper.
set env(FAKE_OP_READ_FAILS) 1
spawn $env(VAULT) restore
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
pick "What should this run do?" 0
expect "record.hex: "; send "$dir/record.hex\r"
answer "share 1: passphrase" n
answer "share 2: 1Password item (Touch ID)" y
answer "share 3: paper share (24 words)" y
answer "it asks for Touch ID?" y
expect "Type the 24 words from the paper instead"
type_words $shareb
type_words $sharec
expect -re {Seed fingerprint: ([0-9a-f]{8})} {
    if {$expect_out(1,string) ne $fp} { fail "fallback fingerprint $expect_out(1,string) is not $fp" }
}
expect eof
puts "\nDIR=$dir FP=$fp REF=$ref"
"#;

fn tool(dir: &std::path::Path, name: &str, body: &str) {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Runs an expect script in a fresh work folder with fake tools on PATH; returns the folder and stdout.
fn run_script(
    name: &str,
    script: &str,
    tools: &[(&str, &str)],
    env: &[(&str, &str)],
) -> Option<(std::path::PathBuf, String)> {
    if Command::new("expect").arg("-v").output().is_err() {
        eprintln!("skipped: `expect` is not installed");
        return None;
    }
    let work = std::env::temp_dir().join(format!("epn-vault-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let bin = work.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for (tool_name, body) in tools {
        tool(&bin, tool_name, body);
    }
    let path = work.join("guided.exp");
    std::fs::write(&path, format!("{HELPERS}{script}")).unwrap();
    let mut cmd = Command::new("expect");
    cmd.arg(&path)
        .current_dir(&work)
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("VAULT", env!("CARGO_BIN_EXE_vault"))
        .env("WORK", &work);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    let transcript = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "{transcript}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some((work, transcript))
}

#[test]
fn backup_then_verify_only_restore() {
    // Both echo the client data hash and rp id they were sent, as libfido2 does (see core/src/fido.rs).
    let cred = "read h; read rp; read user; read uid; printf '%s\\n' \"$h\" \"$rp\" packed AQID Zm9vYmFy AQID AQID";
    let secret = format!("{}AQE=", "AQEB".repeat(10)); // 32 bytes of 0x01
    let assert = format!(
        "read h; read rp; read id; read salt; printf '%s\\n' \"$h\" \"$rp\" AQID AQID {secret}"
    );
    let tools = [("fido2-cred", cred), ("fido2-assert", assert.as_str())];
    let Some((work, transcript)) =
        run_script("guided", SCRIPT, &tools, &[("SEED", SEED), ("TYPO", TYPO)])
    else {
        return;
    };

    let fp = epn_core::seed_fingerprint(&epn_core::bip39::words_to_entropy(SEED).unwrap());
    let dir = work.join(
        transcript
            .rsplit_once("DIR=")
            .unwrap()
            .1
            .split_whitespace()
            .next()
            .unwrap(),
    );
    assert!(
        transcript.contains(&format!("FP={fp}")),
        "fingerprint shown is not the seed's"
    );
    // The seed is never on screen (it is typed hidden), in backup or in verify-only restore.
    assert!(!transcript.contains("sausage"), "seed shown");
    // The test step points to verify only.
    assert!(
        transcript.contains("pick \"Verify only\""),
        "the next steps must point to a verify-only test restore"
    );

    let record_hex = std::fs::read_to_string(dir.join("record.hex")).unwrap();
    let record = epn_core::unhex(&record_hex).unwrap();
    // The 2-of-3 layout (passphrase, YubiKey, paper): format version 2, 152 bytes.
    let h = epn_core::record::parse_record(&record).unwrap();
    assert_eq!(
        (record[0], h.k, h.kinds.len(), record.len()),
        (2, 2, 3, 152)
    );
    let sheet = std::fs::read_to_string(dir.join("recovery-sheet.txt")).unwrap();
    for want in [
        "cast code <address>".to_string(),
        format!("record id:        {}", epn_core::record_id(&record)),
        format!("seed fingerprint: {fp}"),
        format!("record:           {}", record_hex.trim()),
        "credential:       Zm9vYmFy".to_string(),
        "recover restore 0x".to_string(),
        "--key 2=Zm9vYmFy".to_string(),
        "vault restore".to_string(),
    ] {
        assert!(sheet.contains(&want), "sheet lacks {want:?}:\n{sheet}");
    }
    assert!(!dir.join(".write-test").exists());
    std::fs::remove_dir_all(&work).unwrap();
}

/// A fake `op`: `item create ... -` keeps the template's value under its title, `read ... <ref>` returns
/// it. Every argv is logged, so the test can prove the share never travels on a command line. It refuses
/// to run with a service-account or Connect token in its environment: those would override `--account`.
const FAKE_OP: &str = r#"echo "$*" >> "$WORK/op-argv.log"
[ -n "$OP_SERVICE_ACCOUNT_TOKEN$OP_CONNECT_HOST$OP_CONNECT_TOKEN" ] && exit 9
case "$1" in
  item) json=$(cat)
        title=$(printf '%s' "$json" | sed -n 's/.*"title":"\([^"]*\)".*/\1/p')
        printf '%s' "$json" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | tr -d '\n' > "$WORK/op-$title"
        echo "ID: fake" ;;
  read) [ -n "$FAKE_OP_READ_FAILS" ] && exit 1
        for a; do ref=$a; done
        cat "$WORK/op-$(printf '%s' "$ref" | cut -d/ -f4)" ;;
  *) exit 1 ;;
esac"#;

#[test]
fn backup_with_1password_then_verify_only_restore() {
    let Some((work, transcript)) = run_script(
        "1password",
        SCRIPT_1PASSWORD,
        &[("op", FAKE_OP)],
        &[
            ("SEED", SEED),
            ("OP_SERVICE_ACCOUNT_TOKEN", "ops_work"),
            ("OP_CONNECT_TOKEN", "x"),
        ],
    ) else {
        return;
    };
    let fp = epn_core::seed_fingerprint(&epn_core::bip39::words_to_entropy(SEED).unwrap());
    assert!(
        transcript.contains(&format!("FP={fp}")),
        "fingerprint shown is not the seed's"
    );
    assert!(!transcript.contains("sausage"), "seed shown");

    let dir = work.join(
        transcript
            .rsplit_once("DIR=")
            .unwrap()
            .1
            .split_whitespace()
            .next()
            .unwrap(),
    );
    let record =
        epn_core::unhex(&std::fs::read_to_string(dir.join("record.hex")).unwrap()).unwrap();
    // Passphrase on chain, shares 2 (1Password) and 3 (paper) off chain: one masked share, 120 bytes.
    let h = epn_core::record::parse_record(&record).unwrap();
    use epn_core::record::Kind::*;
    assert_eq!(
        (h.k, h.kinds.clone(), record.len()),
        (2, vec![Passphrase, Paper, Paper], 120)
    );

    let title = format!("epn-share-2-{}", epn_core::record_id(&record));
    let reference = format!("op://Personal/{title}/password");
    let stored = std::fs::read_to_string(work.join(format!("op-{title}"))).unwrap();
    assert!(
        epn_core::bip39::share_from_words(&stored).is_ok(),
        "1Password holds a valid share: {stored:?}"
    );
    let argv = std::fs::read_to_string(work.join("op-argv.log")).unwrap();
    // The share's first three words never appear in op's arguments (they went through stdin).
    let start: Vec<&str> = stored.split(' ').take(3).collect();
    assert!(
        !argv.contains(&start.join(" ")),
        "a share went through op's argv:\n{argv}"
    );
    // Every op call names the account: with a work account also signed in, op must never pick one itself.
    assert!(
        argv.lines().count() >= 3
            && argv
                .lines()
                .all(|l| l.contains("--account my.1password.com ")),
        "{argv}"
    );
    assert_eq!(
        argv.matches("item create --account my.1password.com --vault Personal -")
            .count(),
        1,
        "{argv}"
    );
    assert!(
        argv.contains(&format!(
            "read --account my.1password.com --no-newline {reference}"
        )),
        "{argv}"
    );

    let sheet = std::fs::read_to_string(dir.join("recovery-sheet.txt")).unwrap();
    assert!(
        sheet.contains(&format!(
            "1password:        share 2 {reference} account my.1password.com"
        )),
        "{sheet}"
    );
    assert!(
        sheet.contains("1Password item (Touch ID)")
            && !sheet.contains("credential:")
            && !sheet.contains("--key"),
        "{sheet}"
    );
    std::fs::remove_dir_all(&work).unwrap();
}
