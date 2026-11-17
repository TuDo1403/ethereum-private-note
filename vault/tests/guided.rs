//! Drives the interactive `vault` through a pty with `expect` (skipped if it is not installed), with fake
//! `fido2-*` and `op` tools on PATH standing in for YubiKeys and 1Password: `vault plan`, backups of
//! several setups (chosen inline or read from a plan file), verify-only restores and `vault op-store`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const SEED: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
// One letter off and still checksum-valid: exactly the typo a single entry would back up silently.
const TYPO: &str = "legal winner thank year wage sausage worth useful legal winner thank yellow";

/// The seed is typed hidden: not one of its words may be on screen, in backup or in verify-only restore. A run
/// of four of its words in a row, however numbered or wrapped: one word alone can turn up in a random paper share.
fn assert_seed_not_printed_back(transcript: &str) {
    let words: String = transcript
        .chars()
        .map(|c| if c.is_ascii_alphabetic() { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!words.contains("year wave sausage worth"), "seed shown");
}

const HELPERS: &str = r#"
set timeout 300
proc fail {msg} { puts stderr "\nFAIL: $msg"; exit 1 }
# Starts `vault` with the given arguments; every expect then fails on a timeout or an early end.
proc start {args} {
    global spawn_id spawn_out
    spawn $::env(VAULT) {*}$args
    # On several lines: expect 5.45 does not read a one-line braced list as pattern/action pairs.
    expect_after {
        timeout { fail "timeout" }
        eof { fail "unexpected end" }
    }
}
# rpassword prints its prompt before it turns echo off; a person types later than that, a script must
# wait, or the pty echoes the "hidden" seed into the transcript that the test checks for leaks.
# A fixed 0.3 s was not enough on the slow linux-aarch64 runner, so wait until the pty really has
# echo off (up to 10 s). If stty cannot be read the loop just runs out and we send anyway.
proc secret {s} {
    global spawn_out
    for {set i 0} {$i < 200} {incr i} {
        if {![catch {exec stty -a < $spawn_out(slave,name)} st] && [string match "*-echo *" $st]} { break }
        sleep 0.05
    }
    send "$s\r"
}
# Menus and y/n questions (dialoguer) read keys in raw mode once drawn: wait for the prompt, pause like a
# person, then press keys. `pick n` moves down n items and presses Enter.
proc pick {prompt n} { expect -ex $prompt; sleep 0.3; send [string repeat "\033\[B" $n]; send "\r" }
proc answer {prompt key} { expect -ex $prompt; expect -ex {(y/n)}; sleep 0.3; send "$key\r" }
# Hidden words, one per prompt: `secret` waits until the pty has echo off, so no word is echoed into the
# transcript that the test checks for leaks.
proc type_words {words {what {paper share [0-9]+}} {n 24}} {
    set i 0
    foreach w $words {
        incr i
        expect -re "$what, word $i/$n\[^:\]*: "
        secret $w
    }
}
proc words_of {block} {
    set out {}
    foreach {all w} [regexp -all -inline {[0-9]+\. ([a-z]+)} $block] { lappend out $w }
    return $out
}
# The first group of the regex, once it is on the screen.
proc capture {re} { global expect_out; expect -re $re; return $expect_out(1,string) }
# The n numbered words that follow `title` (a regex) on the screen.
proc shown {title n} {
    return [words_of [capture "$title\r\n((?: +\[0-9\]+\\. \[a-z\]+\r\n)\{$n\})"]]
}
# A paper share shown after `title` (a regex) and confirmed as written; returns its words.
proc show_paper {title} {
    set words [shown $title 24]
    expect "type all 24 words back"; send "\r"
    return $words
}
# The seed typed twice; returns the fingerprint shown.
proc enter_seed {{menu 1}} {
    if {$menu} { pick "How many words is your seed?" 0 }
    type_words [split $::env(SEED) " "] seed 12
    type_words [split $::env(SEED) " "] {seed again} 12
    return [capture {Seed fingerprint: ([0-9a-f]{8})}]
}
# The generated passphrase, written down and typed back; returns it.
proc write_passphrase {} {
    set pass [join [shown {passphrase:} 12] " "]
    expect "once it is written down"; send "\r"
    type_words [split $pass " "] passphrase 12
    return $pass
}
# Up to the first question about a share: the setup is accepted, the output folder announced (and made),
# and the user ready. Returns the folder.
proc ready {} {
    set dir [capture {saved in \./(backup-[0-9]+)/}]
    if {![file isdirectory $dir]} { fail "output folder not made before the start" }
    expect "offline and ready."; send "\r"
    return $dir
}
# A verify-only restore of the record at `record`, up to the first question about a share.
proc restore_start {record args} {
    start --allow-unsafe-host restore {*}$args
    pick "What should this run do?" 0
    expect "record.hex: "; send "$record\r"
}
proc fingerprint_is {want} {
    set got [capture {Seed fingerprint: ([0-9a-f]{8})}]
    if {$got ne $want} { fail "verify-only fingerprint $got is not $want" }
    expect eof
}
# The places screen: for each label, an existing place (its index in the list so far) or a new one.
proc place {label index {new ""}} {
    pick "Where will $label be kept?" $index
    if {$new ne ""} { expect "New place"; send "$new\r" }
}
# Which fake YubiKey is plugged in (see KEYS_TOKEN).
proc plug {key} { set f [open "$::env(WORK)/key" w]; puts $f $key; close $f }
# A flag file the fake tools consume: `two` makes the next listing show a second key, `failonce` makes
# the next assertion fail.
proc flag {name} { close [open "$::env(WORK)/$name" w] }
"#;

const SCRIPT: &str = r#"
start --allow-unsafe-host backup --device /dev/fake
pick "How should this backup be split?" 0
answer "Rename any of them?" n
place passphrase 0 home
place YubiKey 1 office
place paper 2 parents
expect "Press Enter to use this setup"; send "\r"
set dir [ready]
expect "make a new one: "; send "\r"
expect "credential id: Zm9vYmFy"

# Seed twice: a checksum-valid typo in the second entry is caught.
pick "How many words is your seed?" 0
type_words [split $env(SEED) " "] seed 12
type_words [split $env(TYPO) " "] {seed again} 12
expect "not the same seed"
set fp [enter_seed 0]
set pass [write_passphrase]

# The public files exist before the paper share is shown.
expect "Self-check passed: every combination of 2 opens the record."
expect "Saved two PUBLIC files"
if {![file exists $dir/record.hex] || ![file exists $dir/recovery-sheet.txt]} { fail "files not saved before the paper share" }
set paper [show_paper {paper share \(this is share 3\):}]

# Typed back wrongly the paper is shown again: words that fail the checksum (Enter gives up on them),
# then a different valid share.
type_words [lrepeat 24 abandon]
expect "Which word number"; send "\r"
expect "That did not match"
expect "try again."; send "\r"
type_words [concat [lrepeat 23 abandon] art]
expect "That did not match"
expect "try again."; send "\r"
type_words $paper
expect "6/6 Backup made"
expect "publish <rpc-url>"
expect eof

# Verify only: the papers open the record, the fingerprint is shown, the seed is not.
restore_start $dir/record.hex
answer "share 1: passphrase" y
answer "share 2: YubiKey (YubiKey and its PIN)" n
answer "share 3: paper (paper share (24 words))" y
type_words [split $pass " "] passphrase 12
type_words $paper
fingerprint_is $fp
puts "\nDIR=$dir FP=$fp"
"#;

fn tool(dir: &Path, name: &str, body: &str) {
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
) -> Option<(PathBuf, String)> {
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

/// The backup folder a script reported as `DIR=<name>`.
fn dir_of(work: &Path, transcript: &str) -> PathBuf {
    let name = transcript.rsplit_once("DIR=").unwrap().1;
    work.join(name.split_whitespace().next().unwrap())
}

fn record_in(dir: &Path) -> Vec<u8> {
    epn_core::unhex(&std::fs::read_to_string(dir.join("record.hex")).unwrap()).unwrap()
}

fn seed_fp() -> String {
    epn_core::seed_fingerprint(&epn_core::bip39::words_to_entropy(SEED).unwrap())
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

    let fp = seed_fp();
    let dir = dir_of(&work, &transcript);
    assert!(
        transcript.contains(&format!("FP={fp}")),
        "fingerprint shown is not the seed's"
    );
    assert_seed_not_printed_back(&transcript);
    // The test step points to verify only.
    assert!(
        transcript.contains("pick \"Verify only\""),
        "the next steps must point to a verify-only test restore"
    );

    let record_hex = std::fs::read_to_string(dir.join("record.hex")).unwrap();
    let record = record_in(&dir);
    // The 2-of-3 layout (passphrase, YubiKey, paper): record format version 1, 152 bytes.
    let h = epn_core::record::parse_record(&record).unwrap();
    assert_eq!(
        (record[0], h.k, h.kinds.len(), record.len()),
        (1, 2, 3, 152)
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
    assert_no_places(&work, &dir);
    assert!(!dir.join(".write-test").exists());
    std::fs::remove_dir_all(&work).unwrap();
}

/// Places score a setup and are shown on screen, but are never written: not on the public files, and no
/// plan file is left behind by a backup that chose its setup inline.
fn assert_no_places(work: &Path, dir: &Path) {
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

/// A custom setup of two 1Password shares in one account and a paper share (no passphrase: no Argon2),
/// scored weak (one account breach opens it) and taken with `yes`. The offline backup never runs `op`;
/// `vault op-store` asks which share to store and stores only that one, under its own share number (run
/// twice: the second run must find the item, not duplicate it). Then verify-only restores read share 2
/// from 1Password, and from its paper when `op read` fails.
const SCRIPT_OP: &str = r#"
start --allow-unsafe-host backup
pick "How should this backup be split?" 4
pick "Add share 1" 3
pick "Add share 2" 3
pick "Add share 3" 2
pick "Add share 4" 4
pick "How many shares should it take" 0
answer "Rename any of them?" n
expect "1Password A\" (sign-in address or email, e.g. my.1password.com): "; send "my.1password.com\r"
expect "lists them): "; send "Personal\r"
# The second share offers the account just entered: another spelling of it could not hide the sharing.
pick "Which 1Password account holds \"1Password B\"?" 0
expect "lists them): "; send "Personal\r"
place "1Password A" 0 home
place "1Password B" 1 office
place paper 2 parents
expect "Theft   ⚠ weak"
expect "one breach of the 1Password account my.1password.com opens it: 1Password A + 1Password B"
expect "type yes"; send "yes\r"
set dir [ready]
set fp [enter_seed]
expect "Self-check passed: every combination of 2 opens the record."
foreach x {1 2} {
    set share($x) [show_paper "share $x for 1Password \\(TEMPORARY paper\\):"]
    type_words $share($x)
}
set share(3) [show_paper {paper share \(this is share 3\):}]
type_words $share(3)
expect "vault op-store $dir/recovery-sheet.txt"
expect eof
if {[file exists "$env(WORK)/op-argv.log"]} { fail "the offline backup ran op" }

foreach run {first second} {
    start op-store $dir/recovery-sheet.txt
    pick "Which 1Password share?" 1
    type_words $share(2)
    expect "Again"
    type_words $share(2)
    if {$run eq "first"} {
        # The item does not exist, so the fake `op read` fails: that is not proof of absence, a person confirms.
        answer "NO item" y
        expect "Share 2 is in 1Password as"
    } else {
        expect "already in 1Password"
    }
    expect eof
}

foreach fails {0 1 2} {
    if {$fails} { set env(FAKE_OP_READ_FAILS) 1 }
    restore_start $dir/record.hex
    answer "share 1: 1Password A" n
    answer "share 2: 1Password B (1Password item (Touch ID))" y
    answer "share 3: paper (paper share (24 words))" y
    answer "it asks for Touch ID?" y
    # A failing `op read` (locked, Touch ID cancelled) must not end the restore: it falls back to the paper.
    if {$fails} { expect "Type the 24 words from the paper instead" }
    if {$fails == 2} {
        # Giving up on a share (an empty answer to "Which word number") leaves it out, and it is offered again.
        type_words [lrepeat 24 abandon]
        expect "Which word number"; send "\r"
        type_words $share(3)
        answer "Enter share 2" y
        answer "Enter share 3" n
        answer "it asks for Touch ID?" y
        expect "Type the 24 words from the paper instead"
        type_words $share(2)
    } else {
        if {$fails} { type_words $share(2) }
        type_words $share(3)
    }
    fingerprint_is $fp
}
puts "\nDIR=$dir FP=$fp"
"#;

#[test]
fn op_store_backup_and_restore() {
    let Some((work, transcript)) = run_script(
        "op",
        SCRIPT_OP,
        &[("op", FAKE_OP)],
        &[
            ("SEED", SEED),
            ("OP_SERVICE_ACCOUNT_TOKEN", "ops_work"),
            ("OP_CONNECT_TOKEN", "x"),
        ],
    ) else {
        return;
    };
    assert!(
        transcript.contains(&format!("FP={}", seed_fp())),
        "fingerprint shown is not the seed's"
    );
    assert_seed_not_printed_back(&transcript);

    let dir = dir_of(&work, &transcript);
    let record = record_in(&dir);
    use epn_core::record::Kind::*;
    let h = epn_core::record::parse_record(&record).unwrap();
    assert_eq!((h.k, h.kinds.clone()), (2, vec![Paper, Paper, Paper]));

    let id = epn_core::record_id(&record);
    let reference = format!("op://Personal/epn-share-2-{id}/password");
    let stored = std::fs::read_to_string(work.join(format!("op-epn-share-2-{id}"))).unwrap();
    assert!(
        epn_core::bip39::share_from_words(&stored).is_ok(),
        "1Password holds a valid share: {stored:?}"
    );
    assert!(!work.join(format!("op-epn-share-1-{id}")).exists());
    let argv = std::fs::read_to_string(work.join("op-argv.log")).unwrap();
    // The share's first three words never appear in op's arguments (they went through stdin).
    let start: Vec<&str> = stored.split(' ').take(3).collect();
    assert!(
        !argv.contains(&start.join(" ")),
        "a share went through op's argv:\n{argv}"
    );
    assert!(!argv.contains("epn-share-1-"), "{argv}");
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
    let want =
        format!("share 2:  1password    \"1Password B\" {reference} account my.1password.com");
    assert!(sheet.contains(&want), "{sheet}");
    assert_no_places(&work, &dir);
    std::fs::remove_dir_all(&work).unwrap();
}

/// Preset 3 (2 of 4) as `vault plan` saves it: no places.
const PLAN3: &str = "epn setup v1\nk 2\nshare 1 passphrase \"passphrase\"\nshare 2 yubikey \"YubiKey A\"\nshare 3 yubikey \"YubiKey B\"\nshare 4 paper \"paper\"\n";

const SCRIPT_PLAN: &str = r#"
start plan
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
    assert_eq!(
        std::fs::read_to_string(work.join("setup.txt")).unwrap(),
        PLAN3
    );
    // The private list is on screen, label by label.
    assert!(transcript.contains("passphrase  home"), "{transcript}");
    std::fs::remove_dir_all(&work).unwrap();
}

/// Fake YubiKeys for several keys. `$WORK/key` names the key plugged in (A or B), `$WORK/two` means a
/// second key is plugged in too (for one listing), and `$WORK/creds-<key>` lists the credentials each key
/// holds. `fido2-token -L -k` fails on a key with no credential for the rp id, as a real key may.
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
/// not on the key plugged in fails, and so does the first assertion after `$WORK/failonce` is made (a wrong PIN).
const KEYS_ASSERT: &str = r#"read h; read rp; read id; read salt
[ -f "$WORK/failonce" ] && { rm "$WORK/failonce"; exit 1; }
grep -qxF "$id" "$WORK/creds-$(cat "$WORK/key")" 2>/dev/null || exit 1
s=$(printf %s "$id" | openssl dgst -sha256 -binary | base64)
printf '%s\n' "$h" "$rp" AQID AQID "$s""#;

/// `vault backup setup.txt` with two YubiKeys: a missed swap (key A still plugged in), both keys plugged
/// in and a wrong PIN are each refused and retried, then a verify-only restore opens the record with the
/// two keys alone.
const SCRIPT_TWO_KEYS: &str = r#"
# A setup file is untrusted input: a bad one is refused before any folder is made.
set f [open "$env(WORK)/bad.txt" w]; puts $f "epn setup v2"; close $f
start --allow-unsafe-host backup bad.txt
expect "bad.txt: the first line must be"
expect eof
if {[llength [glob -nocomplain backup-*]] > 0} { fail "a folder was made for a refused setup file" }

set f [open "$env(WORK)/setup.txt" w]; puts -nonewline $f $env(PLAN); close $f
# --device names one key: refused for two YubiKeys, before any folder is made.
start --allow-unsafe-host backup --device /dev/fake setup.txt
# From a file the setup cannot be changed here, and only Enter accepts it: "no" asks again.
expect "or type back to stop (change it with `vault plan`): "; send "no\r"
expect "Press Enter, or type back."
expect "Press Enter to use this setup"; send "\r"
expect "this setup has 2 YubiKeys: run it without --device"
expect eof
if {[llength [glob -nocomplain backup-*]] > 0} { fail "a folder was made for a refused --device" }

plug A
start --allow-unsafe-host backup setup.txt
expect "places were checked in vault plan"
expect "All 6 combinations that open it"
expect "Press Enter to use this setup"; send "\r"
set dir [ready]
# A pasted id that is not on key A: the first key is not listed (key A holds no credential yet, so the
# fake listing would fail), the secret step fails and says the id is not on the key.
expect "Plug in only YubiKey A, then press Enter."; send "\r"
expect "make a new one: "; send "Zm9v\r"
expect "this credential id is not on the plugged-in key"
# A wrong PIN after the credential is made: the retry keeps that credential and makes no other.
expect "Plug in only YubiKey A, then press Enter."; flag failonce; send "\r"
expect "make a new one: "; send "\r"
expect -re {credential id: (\S+)}
expect "Plug in only YubiKey A, then press Enter."; send "\r"
expect "Enter the YubiKey PIN, then touch"

# The swap to key B is missed: the credential is made on key A, whose listing then shows share 2's id.
expect "Plug in only YubiKey B, then press Enter."; send "\r"
expect "make a new one: "; send "\r"
expect "this is the same key as YubiKey A; plug in YubiKey B"
# Key B plugged in, but key A left in too: told to unplug it, not the raw --device error.
expect "Plug in only YubiKey B, then press Enter."
plug B; flag two
send "\r"
expect "make a new one: "; send "\r"
expect "unplug the other"
expect "Plug in only YubiKey B, then press Enter."
file delete "$env(WORK)/two"
send "\r"
expect "make a new one: "; send "\r"
expect -re {credential id: (\S+)}

set fp [enter_seed]
set pass [write_passphrase]
expect "Self-check passed: every combination of 2 opens the record."
expect "Saved two PUBLIC files"
set paper [show_paper {paper share \(this is share 4\):}]
type_words $paper
expect "7/7 Backup made"
expect eof

# Verify only with the two keys, one at a time: no passphrase, no paper.
restore_start $dir/record.hex
answer "share 1: passphrase" n
answer "share 2: YubiKey A" y
answer "share 3: YubiKey B" y
answer "share 4: paper" n
# Both keys left plugged in: told to unplug one and asked again, not sent to --device.
expect "Plug in only the YubiKey that is share 2"; plug A; flag two; send "\r"
expect "More than one key is plugged in"
expect "Plug in only the YubiKey that is share 2"; file delete "$env(WORK)/two"; send "\r"
expect "Plug in only the YubiKey that is share 3"; plug B; send "\r"
fingerprint_is $fp
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
    assert!(
        transcript.contains(&format!("FP={}", seed_fp())),
        "{transcript}"
    );
    assert_seed_not_printed_back(&transcript);
    let dir = dir_of(&work, &transcript);
    let record = record_in(&dir);
    let h = epn_core::record::parse_record(&record).unwrap();
    use epn_core::record::Kind::*;
    assert_eq!(
        (h.k, h.kinds.clone()),
        (2, vec![Passphrase, Hardware, Hardware, Paper])
    );
    // Share 2 is key A's first credential, share 3 key B's. Key A holds one more, made by the missed swap:
    // the wrong PIN before it made none.
    let creds = |key: &str| -> Vec<String> {
        let text = std::fs::read_to_string(work.join(format!("creds-{key}"))).unwrap();
        text.lines().map(String::from).collect()
    };
    let (a, b) = (creds("A"), creds("B"));
    assert_eq!((a.len(), b.len()), (2, 1));
    let sheet = std::fs::read_to_string(dir.join("recovery-sheet.txt")).unwrap();
    for want in [
        format!("\"YubiKey A\"  credential {}   (rpId localhost)", a[0]),
        format!("\"YubiKey B\"  credential {}   (rpId localhost)", b[0]),
        format!("--key 2={}@<path> --key 3={}@<path>", a[0], b[0]),
    ] {
        assert!(sheet.contains(&want), "sheet lacks {want:?}:\n{sheet}");
    }
    std::fs::remove_dir_all(&work).unwrap();
}

// vectors.json entry 1: 3 of 5 = passphrase, YubiKey, YubiKey, paper, paper. The tests below hold shares
// 2, 3 and 4 (or 2, 4 and 5), so no Argon2 runs.
const ENTRY1_RECORD: &str = "010000040001a0a1a2a3a4a5a6a7a8a9aaabacadaeaf030501020203033f837ba1b51f5c41dbf53e78fc619ef4a24bea9444b63e85fa30e10d8601b51da9410f69a618fa6fd0bf87dc1469dac9e9d0bc07f7fb7e8fd56a9c4cead438f3cd81c75253f05726f6b790d7bbbdd4282aaabbee1e9876412e73ef3b09836e64a5acb3bac1c8cfd6dde4ebf20f04edfdadee4ec815d33e80eba11490ddde601c68f983a0fd2b15d61f884fb404ea4cb97e04f0d0b47414414236fce134";
const ENTRY1_MNEMONIC: &str = "arctic live gadget display excess mandate sniff autumn people disorder affair hole retreat fancy close tip deer village tuition orbit cannon owner maid spare";
const ENTRY1_WORDS4: &str = "flight clock injury host plastic slide across memory patrol raven endless custom leisure caught start crater zero muffin inquiry canal donkey version decide kitchen";
const ENTRY1_WORDS5: &str = "juice clerk lab quit pool room lizard moment library ramp faculty wagon keen crucial feature custom tent normal erupt throw drip tissue reunion grunt";

/// A fake `fido2-assert` that answers with entry 1's share-2 secret for credential `Zm9v` and its share-3
/// secret for `YmFy` (32 bytes 0x52.. and 0x53.., base64), echoing the hash and rp id as libfido2 does. The
/// first assertion after `$WORK/failonce` is made fails (a wrong PIN).
const ENTRY1_ASSERT: &str = r#"read h; read rp; read id; read salt
[ -f "$WORK/failonce" ] && { rm "$WORK/failonce"; exit 1; }
case "$id" in
  Zm9v) s=UlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHE= ;;
  YmFy) s=U1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXI= ;;
  *) exit 1 ;;
esac
printf '%s\n' "$h" "$rp" AQID AQID "$s""#;

/// Runs `script` against entry 1's record, with `sheet` as the recovery-sheet.txt beside record.hex.
fn restore_entry1(name: &str, sheet: &str, script: &str) {
    // `$WORK/two` makes the next listing show a second key.
    let fido2_token = "echo '/dev/fake: vendor=0x1050, product=0x0407 (Yubico YubiKey)'\n\
                       [ -f \"$WORK/two\" ] && { rm \"$WORK/two\"; echo '/dev/fake2: vendor=0x1050, product=0x0407 (fake)'; }\n\
                       exit 0";
    let tools = [
        ("fido2-assert", ENTRY1_ASSERT),
        ("fido2-token", fido2_token),
    ];
    let fp =
        epn_core::seed_fingerprint(&epn_core::bip39::words_to_entropy(ENTRY1_MNEMONIC).unwrap());
    let script = format!(
        r#"
foreach {{file var}} {{record.hex RECORD recovery-sheet.txt SHEET}} {{
    set f [open "$env(WORK)/$file" w]; puts -nonewline $f $env($var); close $f
}}
{script}"#
    );
    let env = [
        ("RECORD", ENTRY1_RECORD),
        ("SHEET", sheet),
        ("FP", fp.as_str()),
        ("WORDS4", ENTRY1_WORDS4),
        ("WORDS5", ENTRY1_WORDS5),
    ];
    if let Some((work, _)) = run_script(name, &script, &tools, &env) {
        std::fs::remove_dir_all(&work).unwrap();
    }
}

/// Two YubiKeys named on a sheet (the lines `sheet::render` writes): the restore takes each credential
/// from its `share N:` line, asks for no credential id, and has the keys plugged in one at a time.
/// `--device` cannot name two keys: refused before any PIN.
#[test]
fn restore_two_keys_from_sheet() {
    let sheet = format!(
        "Recovery sheet.\n\nrecord:           0x{ENTRY1_RECORD}\n\n\
         share 1:  passphrase   \"passphrase\"\n\
         share 2:  yubikey      \"YubiKey A\"  credential Zm9v   (rpId localhost)\n\
         share 3:  yubikey      \"YubiKey B\"  credential YmFy   (rpId localhost)\n\
         share 4:  paper        \"paper A\"\n\
         share 5:  paper        \"paper B\"\n"
    );
    let script = r#"
restore_start $env(WORK)/record.hex --device /dev/fake
answer "share 1: passphrase" n
answer "share 2: YubiKey A (YubiKey and its PIN)" y
answer "share 3: YubiKey B (YubiKey and its PIN)" y
answer "share 4: paper A (paper share (24 words))" y
answer "share 5: paper B" n
expect "you hold 2 YubiKeys: run it without --device"
expect eof

restore_start $env(WORK)/record.hex
answer "share 1: passphrase" n
answer "share 2: YubiKey A (YubiKey and its PIN)" y
answer "share 3: YubiKey B (YubiKey and its PIN)" y
answer "share 4: paper A (paper share (24 words))" y
answer "share 5: paper B" n
foreach {x label} {2 A 3 B} {
    expect {
        -ex "Credential id of the YubiKey" { fail "asked for a credential the sheet has" }
        -ex "Plug in only the YubiKey that is share $x (\"YubiKey $label\"), then press Enter." { send "\r" }
    }
    expect "Enter the PIN"
}
type_words $env(WORDS4)
fingerprint_is $env(FP)
"#;
    restore_entry1("two-keys-sheet", &sheet, script);
}

/// One held key: two keys plugged in is told to unplug one (the sheet's id kept), then a wrong PIN, after
/// which the credential id is asked for instead of trusting the sheet's again. A 1Password line that names
/// another record's item is ignored: share 4 is asked for as paper, with no read from 1Password.
#[test]
fn restore_one_key_retries_and_ignores_foreign_reference() {
    let sheet = format!(
        "record:           0x{ENTRY1_RECORD}\n\
         share 2:  yubikey      \"YubiKey A\"  credential Zm9v   (rpId localhost)\n\
         share 4:  1password    \"paper A\" op://Personal/epn-share-4-0000000000000000/password account my.1password.com\n"
    );
    let script = r#"
flag two
flag failonce
restore_start $env(WORK)/record.hex
answer "share 1: passphrase" n
answer "share 2: YubiKey A (YubiKey and its PIN)" y
answer "share 3: YubiKey and its PIN" n
answer "share 4: paper share (24 words)" y
answer "share 5: paper share (24 words)" y
expect "More than one key is plugged in"
expect "fido2-assert failed"
expect "Credential id of the YubiKey that is share 2"; send "Zm9v\r"
expect "Enter the PIN"
type_words $env(WORDS4)
type_words $env(WORDS5)
fingerprint_is $env(FP)
"#;
    restore_entry1("one-key", &sheet, script);
}
