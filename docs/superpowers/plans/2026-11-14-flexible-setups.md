# Flexible setups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `vault plan` designs and scores any k-of-n setup the format allows (several YubiKeys, papers, 1Password, at most one passphrase), and `vault backup [SETUP]` makes it offline, with a per-share recovery sheet that `vault restore`, `vault op-store` and `recover` all read.

**Architecture:** New focused modules in `vault/src`: `layout.rs` (setup types, validation, presets, plan file), `score.rs` (pure Loss/Theft scoring), `sheet.rs` (recovery sheet render/parse, old and new), `setup.rs` (interactive setup/places/review screens and `vault plan`). `backup.rs` and `restore.rs` are generalised to use them. `core/src/fido.rs` gains a credential listing; `recover` gains `--key X=CRED@PATH`. No record-format change.

**Tech Stack:** Rust 2024 (toolchain pinned 1.94.1), clap, dialoguer, rpassword, zeroize, libfido2 CLI tools (`fido2-cred`, `fido2-assert`, `fido2-token`), `op`; tests with `cargo test` and `expect` driving a pty.

**Spec:** `docs/superpowers/specs/2026-11-14-flexible-setups-design.md` (read it first; this plan argues from it).

## Global Constraints

- Format limits: 2 <= k <= n <= 5, at most one passphrase share. `core` and the record format do not change.
- No new dependencies. Existing ones stay pinned exactly (`=x.y.z`).
- Places are never written to disk: not in `setup.txt`, not on the sheet, not in logs.
- Secrets only at hidden prompts (`ask_hidden`, `enter_paper_share`); never in argv, never in `setup.txt`.
- Secrets in `Zeroizing`; the pads vector is pre-sized with `Vec::with_capacity(n)` so it never reallocates.
- Warn, never block, on weak setups; a weak verdict needs the owner to type `yes`.
- Every backup made by today's `vault` must still restore through `vault restore` (old sheets parse).
- `recover` and SPEC.md alone must restore anything `vault` makes.
- Share order is fixed: passphrase first, then YubiKeys, then paper and 1Password shares, each group in the order chosen.
- Commits: Conventional Commits, scope one of `core, recover, vault, publish, spec, vendor, ci, commitlint, release, deps`. No AI/Claude attribution lines.
- Gate before each commit: `cargo fmt --all --check && cargo clippy --workspace --all-targets --offline --locked -- -D warnings && cargo test --offline --locked -p <crate>`.

## Review Focus

1. A hand-edited, truncated or future-version `setup.txt`: backup refuses it with a message naming the line, before any output folder or secret. Test in Task 1 (`plan_file_rejects_bad_input`).
2. Both YubiKeys plugged in at "plug in only YubiKey B" (`fido2-token -L` lists two): vault says to unplug the other and lets the owner retry, instead of exiting with the raw `--device` error. Test in Task 6 (guided script `two_keys` step).
3. Labels and vault names with spaces, quotes, or non-ASCII ("Tante Hélène's key"): they round-trip through `setup.txt` and the sheet, and a label containing `"` or a newline is refused. Tests in Task 1 and Task 3.
4. A backup made before this change (old sheet: `credential:` line, `1password:  share 2 …` line) restores with its credential and 1Password reference found automatically. Test in Task 3 (`old_sheet_is_read`) and Task 4.
5. A setup with two 1Password shares: `vault op-store` asks which share to store and stores only that one, under `epn-share-<x>-<record id>`. Test in Task 6 (`op_store_picks_share`).

---

### Task 1: Setup types, presets and the plan file (`layout.rs`)

**Files:**
- Create: `vault/src/layout.rs`
- Modify: `vault/src/main.rs` (add `mod layout;`)

**Interfaces:**
- Produces:
  ```rust
  #[derive(Clone, Debug, PartialEq, Eq)]
  pub enum ShareKind { Passphrase, YubiKey, Paper, OnePassword { account: String, vault: String } }
  #[derive(Clone, Debug, PartialEq, Eq)]
  pub struct ShareSpec { pub kind: ShareKind, pub label: String }
  #[derive(Clone, Debug, PartialEq, Eq)]
  pub struct Layout { pub k: usize, pub shares: Vec<ShareSpec> } // shares[i] is share x = i + 1
  impl Layout {
      /// Validates (format limits, labels, 1Password names) and puts shares in the fixed order.
      pub fn new(k: usize, shares: Vec<ShareSpec>) -> Result<Layout, String>;
      pub fn n(&self) -> usize;
      pub fn record_kinds(&self) -> Vec<epn_core::record::Kind>; // OnePassword -> Kind::Paper
      pub fn summary(&self) -> String; // "2 of 4   passphrase · YubiKey A · YubiKey B · paper"
      pub fn to_plan_text(&self) -> String;
      pub fn parse_plan(text: &str) -> Result<Layout, String>;
  }
  /// The four presets in spec order, as (k, shares) not yet validated: the 1Password preset's
  /// account and vault are empty until setup.rs asks for them, then `Layout::new` validates.
  pub fn presets() -> Vec<(usize, Vec<ShareSpec>)>;
  pub fn check_label(s: &str) -> Result<(), String>;
  ```

- [ ] **Step 1: Write the failing tests** in `layout.rs` `#[cfg(test)] mod tests`:

```rust
#[test]
fn new_orders_and_validates() {
    let s = |kind, l: &str| ShareSpec { kind, label: l.into() };
    let l = Layout::new(2, vec![s(ShareKind::Paper, "paper"), s(ShareKind::YubiKey, "YubiKey A"),
                                s(ShareKind::Passphrase, "passphrase")]).unwrap();
    assert_eq!(l.shares.iter().map(|s| s.label.as_str()).collect::<Vec<_>>(),
               ["passphrase", "YubiKey A", "paper"]);
    assert!(Layout::new(1, l.shares.clone()).is_err());            // k < 2
    assert!(Layout::new(4, l.shares.clone()).is_err());            // k > n
    let six = vec![s(ShareKind::Paper, "p"); 6];
    assert!(Layout::new(2, six).is_err());                         // n > 5
    let two_pass = vec![s(ShareKind::Passphrase, "a"), s(ShareKind::Passphrase, "b")];
    assert!(Layout::new(2, two_pass).is_err());                    // one passphrase at most
    let dup = vec![s(ShareKind::Paper, "x"), s(ShareKind::Paper, "x")];
    assert!(Layout::new(2, dup).is_err());                         // labels unique
}

#[test]
fn presets_match_spec() {
    let p = presets();
    assert_eq!(p.iter().map(|(k, s)| (*k, s.len())).collect::<Vec<_>>(), [(2, 3), (2, 3), (2, 4), (3, 5)]);
    let l = |i: usize| Layout::new(p[i].0, p[i].1.clone()).unwrap();
    assert_eq!(l(2).summary(), "2 of 4   passphrase · YubiKey A · YubiKey B · paper");
    assert_eq!(l(0).record_kinds(), [Kind::Passphrase, Kind::Hardware, Kind::Paper]);
    assert!(Layout::new(p[1].0, p[1].1.clone()).is_err()); // 1Password account/vault still empty
}

#[test]
fn plan_file_round_trips() {
    // includes a 1Password share with a spaced vault and a non-ASCII label
    let l = /* 2 of 5: passphrase, YubiKey A, "Tante Hélène's key" (YubiKey), paper,
               OnePassword { account: "my.1password.com", vault: "Private Vault" } */;
    let text = l.to_plan_text();
    assert!(text.starts_with("epn setup v1\n"));
    assert_eq!(Layout::parse_plan(&text).unwrap(), l);
}

#[test]
fn plan_file_rejects_bad_input() {
    for bad in ["", "epn setup v2\nk 2\n", "epn setup v1\nk 2\n" /* no shares */,
                "epn setup v1\nk 2\nshare 1 yubikey \"a\nshare 2 paper \"b\"\n" /* open quote */,
                "epn setup v1\nk 2\nshare 2 paper \"a\"\nshare 1 paper \"b\"\n" /* out of order */,
                "epn setup v1\nk 2\nshare 1 laser \"a\"\nshare 2 paper \"b\"\n" /* unknown kind */] {
        let e = Layout::parse_plan(bad).unwrap_err();
        assert!(!e.is_empty(), "{bad:?}");
    }
    assert!(check_label("a\"b").is_err() && check_label("a\nb").is_err() && check_label("").is_err());
}
```

- [ ] **Step 2: Run** `cargo test --offline --locked -p epn-vault layout` — expect FAIL (module/items not defined).

- [ ] **Step 3: Implement `layout.rs`.** Plan-file syntax (spec example, fixed here):
  `epn setup v1` / `k <k>` / `share <x> passphrase|yubikey|paper "<label>"` / `share <x> 1password "<label>" account <account> vault "<vault>"`.
  Labels and vault names are double-quoted and may not contain `"` or control characters (`check_label`; vault also through `onepassword::check_name`, account through `onepassword::check_account`). Labels: 1..=40 chars. `parse_plan` returns `Err("setup.txt line N: …")` and ends with `Layout::new`, so a parsed file passes the same validation. Share numbers in the file must be 1..=n in order and must already be in the fixed order (refuse otherwise, so the numbers the owner saw in `plan` are the ones backup uses).

- [ ] **Step 4: Run** `cargo test --offline --locked -p epn-vault layout` — expect PASS.

- [ ] **Step 5: Commit** `feat(vault): setup layouts, presets and the plan file`.

---

### Task 2: Scoring (`score.rs`)

**Files:**
- Create: `vault/src/score.rs`
- Modify: `vault/src/main.rs` (add `mod score;`)

**Interfaces:**
- Consumes: `Layout`, `ShareKind` (Task 1).
- Produces:
  ```rust
  #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum Verdict { Weak, Ok, Strong }
  pub struct Score { pub loss: Verdict, pub theft: Verdict, pub warnings: Vec<String>, pub combos: Vec<Vec<usize>> }
  /// combos: every k-subset of share indexes (0-based), lexicographic.
  pub fn combinations(n: usize, k: usize) -> Vec<Vec<usize>>;
  /// places[i] is the place of share i; None = places unknown (backup from setup.txt).
  pub fn score(layout: &Layout, places: Option<&[String]>) -> Score;
  pub fn is_weak(s: &Score) -> bool; // loss or theft is Weak
  ```

- [ ] **Step 1: Write the failing tests** (rules copied from the spec's Scoring section):

```rust
#[test] fn combinations_count() {
    assert_eq!(combinations(4, 2).len(), 6);
    assert_eq!(combinations(5, 3).len(), 10);
    assert_eq!(combinations(3, 2), vec![vec![0, 1], vec![0, 2], vec![1, 2]]);
}
#[test] fn loss_rules() {
    // n - k = 0 -> Weak; 1 -> Ok; >= 2 -> Strong (places all distinct)
    assert_eq!(score(&lay("2of2 pass,key"), None).loss, Verdict::Weak);
    assert_eq!(score(&lay("2of3 pass,key,paper"), None).loss, Verdict::Ok);
    assert_eq!(score(&lay("2of4 pass,key,key,paper"), None).loss, Verdict::Strong);
    // a place holding more than n - k shares -> Weak, warning names the place
    let s = score(&lay("2of4 pass,key,key,paper"), Some(&places(["home", "home", "home", "office"])));
    assert_eq!(s.loss, Verdict::Weak);
    assert!(s.warnings.iter().any(|w| w.contains("a fire at home leaves 1 share")));
}
#[test] fn theft_rules() {
    // every k-subset needs a YubiKey -> Strong
    assert_eq!(score(&lay("3of4 key,key,key,paper"), None).theft, Verdict::Strong);
    // some k-subset is papers only, spread over places -> Ok
    assert_eq!(score(&lay("2of3 pass,key,paper"), Some(&places(["a", "b", "c"]))).theft, Verdict::Ok);
    // one place holds a whole k-subset -> Weak, warning names place and labels
    let s = score(&lay("2of4 pass,key,key,paper"), Some(&places(["home", "home", "office", "parents"])));
    assert_eq!(s.theft, Verdict::Weak);
    assert!(s.warnings.iter().any(|w| w.contains("one break-in at home opens it: passphrase + YubiKey A")));
}
#[test] fn without_places_only_place_free_rules_apply() {
    let s = score(&lay("2of3 pass,key,paper"), None);
    assert_eq!((s.loss, s.theft), (Verdict::Ok, Verdict::Ok));
    assert!(!is_weak(&s));
}
```
  (`lay` and `places` are small test helpers in the test module building a `Layout` with default labels.)

- [ ] **Step 2: Run** `cargo test --offline --locked -p epn-vault score` — expect FAIL.

- [ ] **Step 3: Implement.** Classify each combo: needs a YubiKey if it contains a `YubiKey`; needs an account if it contains `OnePassword` and no `YubiKey`; else papers only. Theft: Weak if any place holds a whole combo; else Ok if any combo is papers only; else Strong. (A papers-only combo with places unknown is Ok, matching the spec's "spread over places" wording; the backup screen notes places were checked in `plan`.) Each warning ends with one suggested fix: `→ keep <label> somewhere else`, or `→ use <k+1> of <n>` when k < n, or `→ add a share`.

- [ ] **Step 4: Run** `cargo test --offline --locked -p epn-vault score` — expect PASS.

- [ ] **Step 5: Commit** `feat(vault): score setups for loss and theft`.

---

### Task 3: The per-share recovery sheet (`sheet.rs`) and per-share 1Password titles

**Files:**
- Create: `vault/src/sheet.rs`
- Modify: `vault/src/onepassword.rs` (remove `pub const X`; add `pub fn title(x: u8, record_id: &str) -> String` = `epn-share-<x>-<record id>`; keep `sheet_line`/`sheet_references` for reading old sheets)
- Modify: `vault/src/main.rs` (`mod sheet;`)

**Interfaces:**
- Consumes: `Layout` (Task 1), `onepassword::{reference, sheet_references, SheetRef}`.
- Produces:
  ```rust
  #[derive(Debug, PartialEq, Eq)]
  pub enum Locator { None, Credential(String), OnePassword { reference: String, account: String } }
  #[derive(Debug, PartialEq, Eq)]
  pub struct SheetShare { pub x: u8, pub label: String, pub locator: Locator }
  /// The whole recovery-sheet.txt text. creds[i] is Some(id) for YubiKey share i.
  pub fn render(record: &[u8], layout: &Layout, creds: &[Option<String>], fingerprint: &str) -> String;
  /// Shares named by a sheet: new `share N:` lines, else the old `credential:` (share 2) and `1password:` lines.
  pub fn parse(sheet: &str) -> Vec<SheetShare>;
  ```

- [ ] **Step 1: Write the failing tests:**

```rust
#[test] fn new_sheet_round_trips() {
    // 2 of 5: passphrase, YubiKey A (cred "Zm9v"), YubiKey B (cred "YmFy"), paper, 1Password A
    let text = render(&record, &layout, &creds, "abcd1234");
    for want in ["share 2:  yubikey      \"YubiKey A\"   credential Zm9v",
                 "share 5:  1password    \"1Password A\" op://Private Vault/epn-share-5-",
                 "--key 2=Zm9v@<path>", "--key 3=YmFy@<path>", "Any 2 of: passphrase, YubiKey A"] {
        assert!(text.contains(want), "{want:?}\n{text}");
    }
    let parsed = parse(&text);
    assert_eq!(parsed[1], SheetShare { x: 2, label: "YubiKey A".into(), locator: Locator::Credential("Zm9v".into()) });
    assert!(matches!(&parsed[4].locator, Locator::OnePassword { account, .. } if account == "my.1password.com"));
}
#[test] fn single_key_sheet_keeps_plain_key_flag() {
    // preset 1: the scripted line is `--key 2=<cred>` without @<path>
}
#[test] fn old_sheet_is_read() {
    let old = "credential:       Zm9vYmFy   (YubiKey, share 2, rpId localhost)\n\
               1password:        share 2 op://Personal/epn-share-2-ab/password account my.1password.com\n";
    let p = parse(old);
    assert!(p.contains(&SheetShare { x: 2, label: String::new(), locator: Locator::Credential("Zm9vYmFy".into()) }));
    assert!(p.iter().any(|s| matches!(&s.locator, Locator::OnePassword { reference, .. } if reference.ends_with("epn-share-2-ab/password"))));
}
```
  (`render` takes no places, by signature. Task 6's inline-backup test checks the saved sheet holds none.)

- [ ] **Step 2: Run** `cargo test --offline --locked -p epn-vault sheet` — expect FAIL.

- [ ] **Step 3: Implement `sheet.rs`.** Move the fixed text of `backup::sheet` here, keeping the record id / record / fingerprint / chain id / address / `cast code` / `vault restore` / `format: SPEC.md` lines and the advice to keep a copy with each factor. Share lines as in the spec's Recovery sheet section; labels quoted, so `parse` reads the label between the first pair of quotes and the locator after it (the 1Password reference is everything up to the last ` account `, as `onepassword::sheet_references` does today, and is validated the same way). Scripted line: `recover restore 0x<record>` then `--key <x>=<cred>` per YubiKey, with `@<path>` appended when the layout has more than one YubiKey, then the stdin lines (`pass <passphrase>`, `paper <x> <24 words>` per paper share, and for 1Password shares `paper <x> <words from \`op read --account <account> <reference>\`>`).

- [ ] **Step 4: Run** `cargo test --offline --locked -p epn-vault` — expect PASS (existing guided tests still pass: backup.rs still writes the old sheet; `onepassword::X` callers in backup/restore temporarily use the literal 2 or `title(2, id)`).

- [ ] **Step 5: Commit** `feat(vault): per-share recovery sheet`.

---

### Task 4: `vault restore` reads every share line

**Files:**
- Modify: `vault/src/restore.rs` (replace `SheetHints` with `Vec<SheetShare>`; labels and locators per x; one key at a time)

**Interfaces:**
- Consumes: `sheet::{parse, SheetShare, Locator}` (Task 3).

- [ ] **Step 1: Write the tests** in `vault/tests/guided.rs`, using the `vectors.json` entry 1 record (3 of 5: passphrase, hardware, hardware, paper, paper; the fake `fido2-assert` returns that vector's share-2 or share-3 secret by the credential id it reads):
  - `restore_two_keys_from_new_sheet` (fails today): a new-format sheet (`sheet::render` output written by hand into the test, labels "YubiKey A"/"YubiKey B", creds `Zm9v`/`YmFy`) beside `record.hex`; `vault restore`, verify only, hold shares 2, 3 and 4 (paper words from the vector); expect no `Credential id of the YubiKey` prompt, expect `Plug in only the YubiKey that is share 3 ("YubiKey B")`, expect the vector's seed fingerprint.
  - `restore_from_old_sheet_finds_credential` (regression, passes today and must keep passing): an old-format sheet with `credential:       Zm9v   (YubiKey, share 2, rpId localhost)`; hold shares 2, 4 and 5; expect no credential prompt for share 2.

- [ ] **Step 2: Run** `cargo test --offline --locked -p epn-vault --test guided restore_` — expect `restore_two_keys_from_new_sheet` to FAIL and the old-sheet test to PASS.

- [ ] **Step 3: Implement.** Prompts use the sheet label when present: `share 3: YubiKey B (YubiKey and its PIN)`. For each held YubiKey share, take its credential from the sheet, else ask (as today). When more than one YubiKey share is held and no `--device` was given, before each key: `Plug in only the YubiKey that is share <x> ("<label>"), then press Enter.` 1Password shares use `Locator::OnePassword` exactly as `op_ref(x)` does today.

- [ ] **Step 4: Run** `cargo test --offline --locked -p epn-vault` — expect PASS.

- [ ] **Step 5: Commit** `feat(vault): restore reads every share on the sheet`.

---

### Task 5: Credential listing in core and `--key X=CRED@PATH` in recover

**Files:**
- Modify: `core/src/fido.rs` (add `pub fn credentials(device: Option<&str>) -> Result<Vec<String>, String>` and private `fn parse_credentials(out: &str) -> Result<Vec<String>, String>`)
- Modify: `recover/src/main.rs` (`--key X=CRED@PATH`; USAGE text)
- Test: `core/src/fido.rs` tests, `recover/tests/cli.rs`

**Interfaces:**
- Produces: `epn_core::fido::credentials(device) -> Result<Vec<String>, String>`: the base64 credential ids the key holds for rpId `localhost`, via `fido2-token -L -k localhost <dev>` (PIN prompted by the tool on the tty, no touch).

- [ ] **Step 1: Write the failing tests:**

```rust
// core/src/fido.rs
#[test] fn credential_listing_is_parsed() {
    // fido2-token(1) -L -k: one "<index>: <credential id> <display name> <user id> <type> <protection>" line per credential
    let out = "00: Zm9vYmFy backup AQID es256 uvopt\n01: YmF6 backup BAUG es256 uvopt\n";
    assert_eq!(parse_credentials(out).unwrap(), ["Zm9vYmFy", "YmF6"]);
    assert_eq!(parse_credentials("").unwrap(), Vec::<String>::new());
    assert!(parse_credentials("00: not-base64! x y z w\n").is_err());
}
```
```rust
// recover/tests/cli.rs
#[test] fn each_key_may_name_its_device() {
    // fake fido2-assert prints a secret chosen by its last argument (the device path):
    // /dev/keyA -> secret of share 2, /dev/keyB -> secret of share 3 (from vectors.json)
    // args: restore <record> --key 2=Zm9v@/dev/keyA --key 3=YmFy@/dev/keyB ; stdin: paper 4 <words>
    // expect success and the vector mnemonic on stdout
    // and: `--key 2=Zm9v@` (empty path) -> exit 2 with a usage error
}
```
  Before Step 3, check the real output shape with `man fido2-token` (section on `-L -k`) and adjust the test's sample line if it differs; the credential id is the field after `<index>:`.

- [ ] **Step 2: Run** `cargo test --offline --locked -p epn-core fido && cargo test --offline --locked -p epn-recover each_key` — expect FAIL.

- [ ] **Step 3: Implement.** `credentials`: `device_path(device)`, then `run("fido2-token", &["-L", "-k", RP_ID, &dev], "")`, then `parse_credentials` (each id through `check_cred_id`). recover: split each `--key` value on the first `@` (base64 has no `@`); a key with its own path uses it, else `--device`, else auto-detect as today.

- [ ] **Step 4: Run** `cargo test --offline --locked -p epn-core && cargo test --offline --locked -p epn-recover` — expect PASS.

- [ ] **Step 5: Commit** `feat(core): list a key's credentials` and `feat(recover): a device per --key` (two commits).

---

### Task 6: Interactive setup and `vault plan`; general `vault backup`

The plan screens and the backup share one code path, and the guided tests exercise both together, so this is one task with two commits.

**Files:**
- Create: `vault/src/setup.rs`
- Modify: `vault/src/main.rs` (`Plan` subcommand; `Backup { setup: Option<String> }`; menu gets "Plan a setup (no secrets)")
- Modify: `vault/src/backup.rs` (drop `Second`, `PASS_X`/`KEY_X`/`PAPER_X`, `sheet`; generalise `build_record`, `backup`, `op_store`)
- Test: `vault/tests/guided.rs`

**Interfaces:**
- Consumes: Tasks 1–3 and 5.
- Produces:
  ```rust
  // setup.rs
  /// Presets or custom, then labels, 1Password account/vault, places, review. Loops until accepted.
  pub fn choose() -> Result<(Layout, Vec<String>), String>;      // (layout, places)
  /// The review screen: summary, Loss/Theft lines, warnings, every combination; Ok(true) = accepted.
  pub fn review(layout: &Layout, places: Option<&[String]>) -> Result<bool, String>;
  /// `vault plan`: choose, save setup.txt (or setup-<n>.txt if taken), show the private
  /// where-things-are list (label -> place) once, clear the screen on Enter.
  pub fn plan() -> Result<(), String>;
  // backup.rs
  pub fn backup(setup: Option<String>, device: Option<String>) -> Result<(), String>;
  fn build_record(entropy: &[u8], pass: Option<&str>, layout: &Layout, prfs: &[(u8, [u8; 32])])
      -> Result<(Vec<u8>, Shares), String>;
  pub fn op_store(sheet_path: &str) -> Result<(), String>;
  ```

- [ ] **Step 1: Write the failing guided tests** (fake tools keep "which key is plugged in" in `$WORK/key`, which the expect script writes with `exec sh -c "echo B > $env(WORK)/key"` when told to plug in key B):
  - fake `fido2-token`: `-L` prints `/dev/fake: vendor=0x1050, product=0x0407 (fake)` (two lines if `$WORK/two` exists); `-L -k localhost /dev/fake` prints one line per id in `$WORK/creds-$(cat $WORK/key)`.
  - fake `fido2-cred`: id = base64 of `key-<letter>-<counter>`, appended to `$WORK/creds-<letter>`.
  - fake `fido2-assert`: secret = 32 bytes derived from the credential id it read (e.g. `printf %s "$id" | shasum -a 256` → base64), so two credentials give two secrets.
  - `plan_scores_and_saves_without_places`: `vault plan`, preset 3 (2 of 4), places home/home/office/parents, expect `one break-in at home opens it: passphrase + YubiKey A`, expect `type yes`, send `yes`; then assert `setup.txt` equals the plan text for preset 3 and contains none of `home`, `office`, `parents`; expect the where-things-are list in the transcript.
  - `backup_two_keys_from_plan`: `vault backup setup.txt`; expect `places were checked in vault plan`; key A enrolled; at `plug in only YubiKey B` do NOT switch the key file, expect `same key as YubiKey A`, then switch to B and continue; create `$WORK/two` once to expect `unplug the other` and a retry (Review Focus 2); seed, passphrase, papers; expect `every combination of 2 opens the record` (6 combinations); assert record header `(k, kinds) = (2, [Passphrase, Hardware, Hardware, Paper])`, sheet has two `credential` lines with different ids and `--key 2=…@<path> --key 3=…@<path>`; then `vault restore` verify only with YubiKey A + YubiKey B (no passphrase, no papers) shows the seed fingerprint.
  - Update `backup_then_verify_only_restore` and `backup_with_1password_then_verify_only_restore` to run `vault backup` with no file, pick presets 1 and 2 at `How should this backup be split?`, give places (`home`, `office`, `parents`), and expect the new sheet lines; add an assertion that `recovery-sheet.txt` and `record.hex` contain none of the place names; keep every leak and order assertion they have.
  - `op_store_picks_share`: custom setup with two 1Password shares; `vault op-store` asks `Which 1Password share?`, stores only that one; fake `op` log shows title `epn-share-<x>-<record id>` (Review Focus 5).

- [ ] **Step 2: Run** `cargo test --offline --locked -p epn-vault --test guided` — expect FAIL.

- [ ] **Step 3: Implement `setup.rs` and the `plan` command.** Screens and copy as in the spec (`How should this backup be split?` menu with five items, custom builder, places from a growing list plus "+ new place", review screen with `Loss`/`Theft` lines and the combination list). Accepting a weak setup requires typing exactly `yes` via `ask`; otherwise Enter via `pause`. Before labels are accepted, warn if a label contains a place name (labels are public). Places live only in a local `Vec<String>`.

- [ ] **Step 4: Commit** `feat(vault): plan and score a setup without secrets`.

- [ ] **Step 5: Implement the general backup.** Steps in the spec's order, numbered `i/N` with N from the layout. With `setup` given: `Layout::parse_plan` (refuse before `output_dir`), show summary and `review(layout, None)` with the note `places were checked in vault plan`. Without: `setup::choose()` inline. Each YubiKey share: if more than one YubiKey and no `--device`, `pause("Plug in only YubiKey B, then press Enter.")`; on `several FIDO2 keys found` say to unplug the others and retry (up to `TRIES`); enroll or paste id; refuse a repeated id; for every key after the first, `fido::credentials` and refuse if an earlier share's id is listed (`this is the same key as YubiKey A; plug in YubiKey B`); then `fido::secret`. Passphrase only if the layout has one. `build_record` checks every `score::combinations(n, k)` subset with `unseal` and prints `Self-check passed: every combination of <k> opens the record.` Save `record.hex` and `sheet::render(…)` before any share is shown. Then each paper and 1Password share in share order with today's show/confirm text (`paper share (this is share <x>)`, 1Password ones as TEMPORARY paper). Next steps list one `vault op-store` line per 1Password share. `op_store`: from `sheet::parse`, the 1Password shares; if more than one, `choose("Which 1Password share?", …)`; title via `onepassword::title(x, record_id)`; the rest unchanged.

- [ ] **Step 6: Run** `cargo test --offline --locked -p epn-vault` — expect PASS. Then the full gate (Global Constraints).

- [ ] **Step 7: Commit** `feat(vault): back up any setup the format allows`.

---

### Task 7: Docs

**Files:**
- Modify: `README.md` (plan step, presets, scoring, places never saved, several YubiKeys and the different-key check, new sheet lines, `--key X=CRED@PATH`; remove the "`vault backup` makes only the 2-of-3 layout" limitation; the line ~376 "v1-only" claim if still present)
- Modify: `SPEC.md` prose only: line 24 (what `vault` makes) and lines 105–113 (1Password share number, item title `epn-share-<x>-<record id>`, sheet line form). Format sections untouched.

- [ ] **Step 1:** Edit both files. Check every command and flag named exists: `cargo run -q -p epn-vault -- --help`, `cargo run -q -p epn-vault -- plan --help`, `cargo run -q -p epn-recover` (usage shows `--key X=CRED_ID[@PATH]`).
- [ ] **Step 2:** `rtk rg -n "2-of-3|share 2|credential:" README.md SPEC.md` — every remaining hit is about old backups or an example of the 2-of-3 preset, not a claim that `vault` only makes it.
- [ ] **Step 3: Commit** `docs(spec): describe flexible setups` (SPEC) and `docs(vault): plan, scoring and several YubiKeys` (README).
