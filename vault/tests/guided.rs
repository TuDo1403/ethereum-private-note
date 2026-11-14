//! Drives the interactive `vault` through a pty with `expect` (skipped if it is not installed), with fake
//! `fido2-*` and `op` tools on PATH standing in for YubiKeys and 1Password: `vault plan`, backups of
//! several setups (chosen inline or read from a plan file), verify-only restores and `vault op-store`.

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
# The places screen: for each label, an existing place (its index in the list so far) or a new one.
proc place {label index {new ""}} {
    pick "Where will $label be kept?" $index
    if {$new ne ""} { expect "New place"; send "$new\r" }
}
# Which fake YubiKey is plugged in (see KEYS_TOKEN).
proc plug {key} { set f [open "$::env(WORK)/key" w]; puts $f $key; close $f }
"#;

const SCRIPT: &str = r#"
spawn $env(VAULT) backup --device /dev/fake
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
pick "How should this backup be split?" 0
answer "Rename any of them?" n
place passphrase 0 home
place YubiKey 1 office
place paper 2 parents
expect "Press Enter to use this setup"; send "\r"
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

# The public files exist before the paper share is shown.
expect "Self-check passed: every combination of 2 opens the record."
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
answer "share 2: YubiKey (YubiKey and its PIN)" n
answer "share 3: paper (paper share (24 words))" y
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
pick "How should this backup be split?" 1
answer "Rename any of them?" n
expect "PERSONAL 1Password account"
expect "e.g. my.1password.com): "; send "my.1password.com\r"
expect "lists them): "; send "Personal\r"
expect "OUT of"
place passphrase 0 home
place 1Password 1 office
place paper 2 parents
expect "Press Enter to use this setup"; send "\r"
expect -re {saved in \./(backup-[0-9]+)/} { set dir $expect_out(1,string) }
expect "offline and ready."; send "\r"
expect "Type your seed words"; secret $env(SEED)
expect "Type them again"; secret $env(SEED)
expect -re {Seed fingerprint: ([0-9a-f]{8})} { set fp $expect_out(1,string) }
expect -re {passphrase:\r\n((?: +[0-9]+\. [a-z]+\r\n){7})} { set pass [join [words_of $expect_out(1,string)] " "] }
expect "once it is written down"; send "\r"
expect "passphrase: "; send "$pass\r"
expect "Saved two PUBLIC files"
# Shares are shown in share order: the 1Password share (2) before the paper share (3).
expect -re {share 2 for 1Password \(TEMPORARY paper\):\r\n((?: +[0-9]+\. [a-z]+\r\n){24})} { set shareb [words_of $expect_out(1,string)] }
expect "type all 24 words back"; send "\r"
type_words $shareb
expect -re {paper share \(this is share 3\):\r\n((?: +[0-9]+\. [a-z]+\r\n){24})} { set sharec [words_of $expect_out(1,string)] }
expect "type all 24 words back"; send "\r"
type_words $sharec
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
answer "share 2: 1Password (1Password item (Touch ID))" y
answer "share 3: paper (paper share (24 words))" y
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
answer "share 2: 1Password (1Password item (Touch ID))" y
answer "share 3: paper (paper share (24 words))" y
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
        "share 1:  passphrase   \"passphrase\"".to_string(),
        "share 2:  yubikey      \"YubiKey\"    credential Zm9vYmFy   (rpId localhost)".to_string(),
        "share 3:  paper        \"paper\"".to_string(),
        "recover restore 0x".to_string(),
        "--key 2=Zm9vYmFy".to_string(),
        "vault restore".to_string(),
    ] {
        assert!(sheet.contains(&want), "sheet lacks {want:?}:\n{sheet}");
    }
    assert!(
        !sheet.contains("@<path>"),
        "one key needs no path:\n{sheet}"
    );
    assert_no_places(&work, &dir);
    assert!(!dir.join(".write-test").exists());
    std::fs::remove_dir_all(&work).unwrap();
}

/// Places score a setup and are shown on screen, but are never written: not on the public files, and no
/// plan file is left behind by a backup that chose its setup inline.
fn assert_no_places(work: &std::path::Path, dir: &std::path::Path) {
    for file in ["record.hex", "recovery-sheet.txt"] {
        let text = std::fs::read_to_string(dir.join(file)).unwrap();
        for place in PLACES {
            assert!(
                !text.contains(place),
                "{file} names the place {place}:\n{text}"
            );
        }
    }
    assert!(
        !work.join("setup.txt").exists(),
        "a backup saved a setup file"
    );
}

const PLACES: [&str; 3] = ["home", "office", "parents"];

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
            "share 2:  1password    \"1Password\"  {reference} account my.1password.com"
        )),
        "{sheet}"
    );
    assert!(
        !sheet.contains("credential") && !sheet.contains("--key"),
        "{sheet}"
    );
    assert_no_places(&work, &dir);
    std::fs::remove_dir_all(&work).unwrap();
}

/// Preset 3 (2 of 4) as `vault plan` saves it: no places.
const PLAN3: &str = "epn setup v1\nk 2\nshare 1 passphrase \"passphrase\"\nshare 2 yubikey \"YubiKey A\"\nshare 3 yubikey \"YubiKey B\"\nshare 4 paper \"paper\"\n";

const SCRIPT_PLAN: &str = r#"
spawn $env(VAULT) plan
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
pick "How should this backup be split?" 2
answer "Rename any of them?" n
place passphrase 0 home
place "YubiKey A" 0
place "YubiKey B" 1 office
place paper 2 parents
expect "Loss    ✓ strong"
expect "one break-in at home opens it: passphrase + YubiKey A"
expect "All 6 combinations that open it"
expect "type yes"; send "yes\r"
expect -re {Saved (\S+)}
expect "Where things are"
expect -re {YubiKey B +office}
expect "clear the screen"; send "\r"
expect eof
"#;

#[test]
fn plan_scores_and_saves_without_places() {
    let Some((work, transcript)) = run_script("plan", SCRIPT_PLAN, &[], &[]) else {
        return;
    };
    let saved = std::fs::read_to_string(work.join("setup.txt")).unwrap();
    assert_eq!(saved, PLAN3);
    for place in PLACES {
        assert!(!saved.contains(place), "setup.txt names {place}");
    }
    // The private list is on screen, label by label.
    assert!(transcript.contains("passphrase  home"), "{transcript}");
    std::fs::remove_dir_all(&work).unwrap();
}

/// Fake YubiKeys for several keys. `$WORK/key` names the key plugged in (A or B), `$WORK/two` means a
/// second key is plugged in too, and `$WORK/creds-<key>` lists the credentials each key holds.
/// `fido2-token -L -k` fails on a key with no credential for the rp id, as a real key may.
const KEYS_TOKEN: &str = r#"if [ "$2" = "-k" ]; then
  f="$WORK/creds-$(cat "$WORK/key")"
  [ -f "$f" ] || exit 1
  i=0; while read -r id; do printf '%02d: %s backup AQID es256 uvopt\n' "$i" "$id"; i=$((i+1)); done < "$f"
else
  echo '/dev/fake: vendor=0x1050, product=0x0407 (fake)'
  [ -f "$WORK/two" ] && echo '/dev/fake2: vendor=0x1050, product=0x0407 (fake)'
fi
exit 0"#;
/// A new credential `key-<key>-<counter>` (base64) on the key plugged in.
const KEYS_CRED: &str = r#"read h; read rp; read user; read uid
key=$(cat "$WORK/key"); f="$WORK/creds-$key"
n=0; [ -f "$f" ] && n=$(wc -l < "$f")
id=$(printf 'key-%s-%s' "$key" $((n + 1)) | base64)
echo "$id" >> "$f"
printf '%s\n' "$h" "$rp" packed AQID "$id" AQID"#;
/// The secret is SHA-256 of the credential id, so two credentials give two secrets; a credential that is
/// not on the key plugged in fails.
const KEYS_ASSERT: &str = r#"read h; read rp; read id; read salt
grep -qxF "$id" "$WORK/creds-$(cat "$WORK/key")" 2>/dev/null || exit 1
s=$(printf %s "$id" | openssl dgst -sha256 -binary | base64)
printf '%s\n' "$h" "$rp" AQID AQID "$s""#;

/// `vault backup setup.txt` with two YubiKeys: a missed swap (key A still plugged in) and both keys plugged
/// in are each refused and retried, then a verify-only restore opens the record with the two keys alone.
const SCRIPT_TWO_KEYS: &str = r#"
# A setup file is untrusted input: a bad one is refused before any folder is made.
set f [open "$env(WORK)/bad.txt" w]; puts $f "epn setup v2"; close $f
spawn $env(VAULT) backup bad.txt
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
expect "the first line must be"
expect eof
if {[llength [glob -nocomplain backup-*]] > 0} { fail "a folder was made for a refused setup file" }

set f [open "$env(WORK)/setup.txt" w]; puts -nonewline $f $env(PLAN); close $f
plug A
spawn $env(VAULT) backup setup.txt
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
expect "places were checked in vault plan"
expect "All 6 combinations that open it"
expect "Press Enter to use this setup"; send "\r"
expect -re {saved in \./(backup-[0-9]+)/} { set dir $expect_out(1,string) }
expect "offline and ready."; send "\r"
expect "Plug in only YubiKey A, then press Enter."; send "\r"
expect "make a new one: "; send "\r"
expect -re {credential id: (\S+)}

# The swap to key B is missed: the credential is made on key A, whose listing then shows share 2's id.
expect "Plug in only YubiKey B, then press Enter."; send "\r"
expect "make a new one: "; send "\r"
expect "this is the same key as YubiKey A; plug in YubiKey B"
# Key B plugged in, but key A left in too: told to unplug it, not the raw --device error.
expect "Plug in only YubiKey B, then press Enter."
plug B; close [open "$env(WORK)/two" w]
send "\r"
expect "make a new one: "; send "\r"
expect "unplug the other"
expect "Plug in only YubiKey B, then press Enter."
file delete "$env(WORK)/two"
send "\r"
expect "make a new one: "; send "\r"
expect -re {credential id: (\S+)}

expect "Type your seed words"; secret $env(SEED)
expect "Type them again"; secret $env(SEED)
expect -re {Seed fingerprint: ([0-9a-f]{8})} { set fp $expect_out(1,string) }
expect -re {passphrase:\r\n((?: +[0-9]+\. [a-z]+\r\n){7})} { set pass [join [words_of $expect_out(1,string)] " "] }
expect "once it is written down"; send "\r"
expect "passphrase: "; send "$pass\r"
expect "Self-check passed: every combination of 2 opens the record."
expect "Saved two PUBLIC files"
expect -re {paper share \(this is share 4\):\r\n((?: +[0-9]+\. [a-z]+\r\n){24})} { set shared [words_of $expect_out(1,string)] }
expect "type all 24 words back"; send "\r"
type_words $shared
expect "7/7 Backup made"
expect eof

# Verify only with the two keys, one at a time: no passphrase, no paper.
spawn $env(VAULT) restore
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
pick "What should this run do?" 0
expect "record.hex: "; send "$dir/record.hex\r"
answer "share 1: passphrase" n
answer "share 2: YubiKey A" y
answer "share 3: YubiKey B" y
answer "share 4: paper" n
# Both keys left plugged in: told to unplug one and asked again, not sent to --device.
expect "Plug in only the YubiKey that is share 2"; plug A; close [open "$env(WORK)/two" w]; send "\r"
expect "More than one key is plugged in"
expect "Plug in only the YubiKey that is share 2"; file delete "$env(WORK)/two"; send "\r"
expect "Plug in only the YubiKey that is share 3"; plug B; send "\r"
expect -re {Seed fingerprint: ([0-9a-f]{8})} {
    if {$expect_out(1,string) ne $fp} { fail "verify-only fingerprint $expect_out(1,string) is not $fp" }
}
expect eof
puts "\nDIR=$dir FP=$fp"
"#;

#[test]
fn backup_two_keys_from_plan() {
    let tools = [
        ("fido2-token", KEYS_TOKEN),
        ("fido2-cred", KEYS_CRED),
        ("fido2-assert", KEYS_ASSERT),
    ];
    let Some((work, transcript)) = run_script(
        "two-keys",
        SCRIPT_TWO_KEYS,
        &tools,
        &[("SEED", SEED), ("PLAN", PLAN3)],
    ) else {
        return;
    };
    let fp = epn_core::seed_fingerprint(&epn_core::bip39::words_to_entropy(SEED).unwrap());
    assert!(transcript.contains(&format!("FP={fp}")), "{transcript}");
    assert!(!transcript.contains("sausage"), "seed shown");
    // With several keys plugged in, backup and restore say to unplug one, never to use --device.
    assert!(!transcript.contains("with --device"), "{transcript}");
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
    let h = epn_core::record::parse_record(&record).unwrap();
    use epn_core::record::Kind::*;
    assert_eq!(
        (h.k, h.kinds.clone()),
        (2, vec![Passphrase, Hardware, Hardware, Paper])
    );
    // Share 2 is key A's first credential, share 3 key B's (key A's second, made by the missed swap, is unused).
    let first = |key: &str| {
        std::fs::read_to_string(work.join(format!("creds-{key}")))
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string()
    };
    let (a, b) = (first("A"), first("B"));
    assert_ne!(a, b);
    let sheet = std::fs::read_to_string(dir.join("recovery-sheet.txt")).unwrap();
    for want in [
        format!("\"YubiKey A\"  credential {a}   (rpId localhost)"),
        format!("\"YubiKey B\"  credential {b}   (rpId localhost)"),
        format!("--key 2={a}@<path> --key 3={b}@<path>"),
    ] {
        assert!(sheet.contains(&want), "sheet lacks {want:?}:\n{sheet}");
    }
    std::fs::remove_dir_all(&work).unwrap();
}

/// A custom setup with two 1Password shares in one account and a paper share (no passphrase: no Argon2):
/// scored weak (one account breach opens it) and taken with `yes`; `vault op-store` asks which share to
/// store and stores only that one, under its own share number.
const SCRIPT_OP_PICK: &str = r#"
spawn $env(VAULT) backup
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
pick "How should this backup be split?" 4
pick "Add share 1" 3
pick "Add share 2" 3
pick "Add share 3" 2
pick "Add share 4" 4
pick "How many shares should it take" 0
answer "Rename any of them?" n
foreach label {A B} {
    expect "1Password $label\" (sign-in address or email, e.g. my.1password.com): "; send "my.1password.com\r"
    expect "lists them): "; send "Personal\r"
}
place "1Password A" 0 home
place "1Password B" 1 office
place paper 2 parents
# Both 1Password shares are in one account: one breach opens it, so the setup is weak whatever the places.
expect "Theft   ⚠ weak"
expect "one breach of the 1Password account my.1password.com opens it: 1Password A + 1Password B"
expect "type yes"; send "yes\r"
expect -re {saved in \./(backup-[0-9]+)/} { set dir $expect_out(1,string) }
expect "offline and ready."; send "\r"
expect "Type your seed words"; secret $env(SEED)
expect "Type them again"; secret $env(SEED)
expect "Self-check passed: every combination of 2 opens the record."
foreach x {1 2} {
    expect -re "share $x for 1Password \\(TEMPORARY paper\\):\r\n((?: +\[0-9\]+\\. \[a-z\]+\r\n){24})" { set share($x) [words_of $expect_out(1,string)] }
    expect "type all 24 words back"; send "\r"
    type_words $share($x)
}
expect -re {paper share \(this is share 3\):\r\n((?: +[0-9]+\. [a-z]+\r\n){24})} { set share(3) [words_of $expect_out(1,string)] }
expect "type all 24 words back"; send "\r"
type_words $share(3)
expect "Backup made"
expect eof

spawn $env(VAULT) op-store $dir/recovery-sheet.txt
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
pick "Which 1Password share?" 1
type_words $share(2)
expect "Again"
type_words $share(2)
answer "NO item" y
expect "Share 2 is in 1Password as"
expect eof
puts "\nDIR=$dir"
"#;

#[test]
fn op_store_picks_share() {
    let Some((work, transcript)) = run_script(
        "op-pick",
        SCRIPT_OP_PICK,
        &[("op", FAKE_OP)],
        &[("SEED", SEED)],
    ) else {
        return;
    };
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
    let id = epn_core::record_id(&record);
    let stored = std::fs::read_to_string(work.join(format!("op-epn-share-2-{id}"))).unwrap();
    assert!(epn_core::bip39::share_from_words(&stored).is_ok());
    assert!(!work.join(format!("op-epn-share-1-{id}")).exists());
    let argv = std::fs::read_to_string(work.join("op-argv.log")).unwrap();
    assert!(
        argv.contains(&format!("op://Personal/epn-share-2-{id}/password")),
        "{argv}"
    );
    assert!(!argv.contains("epn-share-1-"), "{argv}");
    assert_eq!(argv.matches("item create").count(), 1, "{argv}");
    std::fs::remove_dir_all(&work).unwrap();
}

// vectors.json entry 1: 3 of 5 = passphrase, YubiKey, YubiKey, paper, paper. The tests below hold shares
// 2, 3 and 4 (or 2, 4 and 5), so no Argon2 runs.
const V1_RECORD: &str = "020000040001a0a1a2a3a4a5a6a7a8a9aaabacadaeaf03050102020303375e1076118f6220d163af412c125935ed642cb3db64a25ff41681b626ad677f9a9e62092c14ecc6ec307a2ed3576671fdeb150a5ef9885730a6b68b18294ac4e6b6e116875adbc39b8fa68c5677086dc3fdb2f87188f8203083667d1b89400ca5acb3bac1c8cfd6dde4ebf20f04edfdadee4ec815d33e80eba11490ddde601c68f983a0fd2b15d61f884fb4046a0556b5f9b4c8e3926a9667c57850e8";
const V1_MNEMONIC: &str = "arctic live gadget display excess mandate sniff autumn people disorder affair hole retreat fancy close tip deer village tuition orbit cannon owner maid spare";
const V1_WORDS4: &str = "flight clock injury host plastic slide across memory patrol raven endless custom leisure caught start crater zero muffin inquiry canal donkey version decide kitchen";
const V1_WORDS5: &str = "juice clerk lab quit pool room lizard moment library ramp faculty wagon keen crucial feature custom tent normal erupt throw drip tissue reunion grunt";

/// A fake `fido2-assert` that answers with entry 1's share-2 secret for credential `Zm9v` and its share-3
/// secret for `YmFy` (32 bytes 0x52.. and 0x53.., base64), echoing the hash and rp id as libfido2 does.
const V1_ASSERT: &str = r#"read h; read rp; read id; read salt
case "$id" in
  Zm9v) s=UlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHE= ;;
  YmFy) s=U1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXI= ;;
  *) exit 1 ;;
esac
printf '%s\n' "$h" "$rp" AQID AQID "$s""#;

/// Runs `script` against entry 1's record, with `sheet` as the recovery-sheet.txt beside record.hex.
fn restore_v1(name: &str, sheet: &str, script: &str) {
    let fido2_token = "echo '/dev/fake: vendor=0x1050, product=0x0407 (Yubico YubiKey)'";
    let tools = [("fido2-assert", V1_ASSERT), ("fido2-token", fido2_token)];
    let fp = epn_core::seed_fingerprint(&epn_core::bip39::words_to_entropy(V1_MNEMONIC).unwrap());
    let script = format!(
        r#"
foreach {{file var}} {{record.hex RECORD recovery-sheet.txt SHEET}} {{
    set f [open "$env(WORK)/$file" w]; puts -nonewline $f $env($var); close $f
}}
{script}"#
    );
    let env = [
        ("RECORD", V1_RECORD),
        ("SHEET", sheet),
        ("FP", fp.as_str()),
        ("WORDS4", V1_WORDS4),
        ("WORDS5", V1_WORDS5),
    ];
    if let Some((work, _)) = run_script(name, &script, &tools, &env) {
        std::fs::remove_dir_all(&work).unwrap();
    }
}

/// Verify-only restore start: the mode menu, then the record path.
const V1_START: &str = r#"
expect_after { timeout { fail "timeout" } eof { fail "unexpected end" } }
pick "What should this run do?" 0
expect "record.hex: "; send "$env(WORK)/record.hex\r"
"#;

const V1_END: &str = r#"
expect -re {Seed fingerprint: ([0-9a-f]{8})} {
    if {$expect_out(1,string) ne $env(FP)} { fail "fingerprint $expect_out(1,string) is not $env(FP)" }
}
expect eof
"#;

/// Two YubiKeys named on a new-format sheet (the lines `sheet::render` writes): the restore takes each
/// credential from its `share N:` line, asks for no credential id, and has the keys plugged in one at a time.
#[test]
fn restore_two_keys_from_new_sheet() {
    let sheet = format!(
        "Recovery sheet.\n\nrecord:           0x{V1_RECORD}\n\n\
         share 1:  passphrase   \"passphrase\"\n\
         share 2:  yubikey      \"YubiKey A\"  credential Zm9v   (rpId localhost)\n\
         share 3:  yubikey      \"YubiKey B\"  credential YmFy   (rpId localhost)\n\
         share 4:  paper        \"paper A\"\n\
         share 5:  paper        \"paper B\"\n"
    );
    let script = format!(
        r#"
spawn $env(VAULT) restore
{V1_START}
answer "share 1: passphrase" n
answer "share 2: YubiKey A (YubiKey and its PIN)" y
answer "share 3: YubiKey B (YubiKey and its PIN)" y
answer "share 4: paper A (paper share (24 words))" y
answer "share 5: paper B" n
foreach {{x label}} {{2 A 3 B}} {{
    expect {{
        -ex "Credential id of the YubiKey" {{ fail "asked for a credential the sheet has" }}
        -ex "Plug in only the YubiKey that is share $x (\"YubiKey $label\"), then press Enter." {{ send "\r" }}
    }}
    expect "Enter the PIN"
}}
type_words $env(WORDS4)
{V1_END}"#
    );
    restore_v1("new-sheet", &sheet, &script);
}

/// Every backup made before setups were flexible must still restore: its sheet has one `credential:` line.
#[test]
fn restore_from_old_sheet_finds_credential() {
    let sheet = format!(
        "record:           0x{V1_RECORD}\n\
         credential:       Zm9v   (YubiKey, share 2, rpId localhost)\n"
    );
    let script = format!(
        r#"
spawn $env(VAULT) restore --device /dev/fake
{V1_START}
answer "share 1: passphrase" n
answer "share 2: YubiKey and its PIN" y
answer "share 3: YubiKey and its PIN" n
answer "share 4: paper share (24 words)" y
answer "share 5: paper share (24 words)" y
expect {{
    -ex "Credential id of the YubiKey" {{ fail "asked for a credential the sheet has" }}
    -ex "Enter the PIN"
}}
type_words $env(WORDS4)
type_words $env(WORDS5)
{V1_END}"#
    );
    restore_v1("old-sheet", &sheet, &script);
}
