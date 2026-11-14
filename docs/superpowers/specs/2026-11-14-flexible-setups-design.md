# Flexible setups: `vault plan` and a general `vault backup`

Project 1 of 3. Project 2 (add or replace a YubiKey later) and project 3 (phone and laptop passkeys) build on
this and are out of scope here.

## Intent

Today `vault backup` makes one setup: 2-of-3 with passphrase (share 1), a YubiKey or a 1Password item
(share 2) and a paper share (share 3). The record format already allows any k-of-n with
2 <= k <= n <= 5, any number of hardware and paper shares and at most one passphrase share
(`core/src/record.rs`, SPEC.md). The owner wants to use that freedom, starting with
"2 YubiKeys + passphrase + paper", and wants the tool to tell them, before they commit, whether a setup
is weak: easy to lose, or easy to steal.

The flow must stay understandable as setups grow to 5 shares, and must be a base for project 2 (adding
or replacing a YubiKey later), which needs a recovery sheet that describes every share.

## Goals

1. Choose any setup the format allows: a preset or a custom list of shares, then the threshold k.
2. Score the setup with two separate verdicts, Loss and Theft, using where each share will be kept, and
   warn about weak setups. Warn, never block.
3. Let the owner design and score setups with no secrets, on any machine (online is fine): `vault plan`.
4. `vault backup` makes any such setup offline, including several YubiKeys and several paper or
   1Password shares.
5. The recovery sheet names every share (number, kind, label, and the credential id or 1Password
   reference), so restore never asks the owner to paste a credential.

## Non-goals

- Adding, replacing or removing shares of an existing backup (project 2).
- Platform passkeys (project 3).
- Any change to the record format or `core` (the format already allows every setup here). SPEC.md's
  format sections stay frozen; its prose about what `vault` makes (line 24, the 1Password section around
  lines 105-113: share 2 only, `epn-share-2-…`, the `1password:` sheet line) is updated to match this
  design. (Builder's call, settled in review.)
- A non-interactive `--layout` flag. The plan file covers reuse.

## Anti-goals (a failure even if it works)

- Places written anywhere on disk: not in the plan file, not on the recovery sheet, not in any log. A file
  that says where each share lives is a map for a thief.
- A weak setup made without the owner having seen, and typed past, the warning that names it.
- Old backups (made by the current `vault`) that no longer restore through `vault restore`.
- Any secret in the plan file or on a command line.

## Constraints

- Format limits: n <= 5, k >= 2, at most one passphrase share. Enforce them in the plan/custom builder
  with plain messages; `new_header` also enforces them.
- `vault` stays interactive only (it refuses pipes today). Secrets only at hidden prompts.
- Backup runs offline. `vault plan` needs no secrets, so it may run online.
- `recover` and SPEC.md must still restore anything `vault` makes with no help from `vault`.
  `recover restore` takes several `--key X=CRED` but only one `--device`, and asks for every key back to
  back, so a combination of two YubiKeys cannot be restored by it today. Change `recover`: each key may
  name its own device, `--key X=CRED@PATH` (both keys plugged in, `fido2-token -L` lists the paths);
  `--key X=CRED` without a path keeps today's behaviour. The sheet's scripted line shows the `@PATH`
  form when the setup has more than one YubiKey. (Builder's call, settled in review.)
- With several FIDO2 keys plugged in, `fido::device_path` refuses to guess unless `--device` is given.
- Keep secrets in `Zeroizing` as today; the pads vector is pre-sized so it never reallocates.

## Approaches considered

- **A. Generalise `backup.rs` in place.** A `Layout` replaces the fixed share numbers; setup is chosen
  inside the backup run. Least code, but you can only try setups while offline with the seed at hand.
- **B. A layout file only.** The wizard writes a file and backup reads it. Dropped: the file would hold
  the places.
- **C. A separate `vault plan` step (chosen).** A secret-free command to design and score setups, which
  writes a plan file without places; `vault backup` reads it. The owner picked C to experiment with
  setups without going offline or typing the seed.

## Design

### Shares, labels, places

Each share in a setup has:

- a **kind** as the owner sees it: passphrase, YubiKey, paper, or 1Password. (1Password is a paper-kind
  share in the record that lives in a 1Password item, as today; see `vault/src/onepassword.rs`.)
- a **label**: neutral, shown on the sheet and in prompts. Defaults: "passphrase", "YubiKey A",
  "YubiKey B", "paper A", "paper B", "1Password A". The owner may rename. Labels go on the public sheet,
  so the plan step tells the owner not to put places in them.
- for 1Password: the **account** and **vault** (checked with `check_account` / `check_name` as today).
- a **place**: free text from a list the owner builds ("home safe", "office", ...). Used only for scoring
  and the private "where things are" list. Never written to disk.

Share numbers (x = 1..n) follow the order of the list. The passphrase, if present, is put first (x = 1),
then YubiKeys, then paper and 1Password shares, so the same setup always gets the same numbers.

### `vault plan`

No secrets, no output directory, any machine.

1. **Choose a setup.**

   ```
   How should this backup be split?
     1. 2 of 3   passphrase · YubiKey · paper              (today's setup)
     2. 2 of 3   passphrase · 1Password · paper            (today's 1Password setup)
     3. 2 of 4   passphrase · YubiKey A · YubiKey B · paper
     4. 3 of 5   passphrase · YubiKey A · YubiKey B · paper A · paper B
     5. Custom   pick each share, then the threshold
   ```

   Custom: add shares one at a time (passphrase at most once, at most 5 shares, at least 2), then choose
   k from 2..=n. Then labels (defaults offered) and, for each 1Password share, account and vault.

2. **Places.** For each share, pick a place from the places named so far or add a new one.

3. **Review and score** (below). The owner can go back and change the setup or places, or accept.

4. **Save** `setup.txt` in the current directory (name it `setup-<n>.txt` if one exists), without places.
   Print the private "where things are" list (label -> place) once, with a note to write it down
   privately or remember it, then clear the screen on Enter.

### Scoring

Computed by a pure function over (kinds, k, places), unit tested. Minimal opening combinations are
exactly the k-subsets, at most C(5,2) = 10, so everything is enumerated.

**Loss** (can you still restore after losing things):

- weak if n - k = 0 ("losing any one share locks you out"), or if some place holds more than n - k
  shares ("a fire at <place> leaves <m> shares; you need <k>").
- ok if n - k = 1, strong if n - k >= 2 (and no place-loss warning).

**Theft** (the cheapest combination a thief needs), each k-subset classed by what it needs:

- needs a YubiKey: contains a YubiKey share (key + PIN, the key locks after 8 wrong PINs).
- needs an account: contains a 1Password share but no YubiKey.
- papers only: only passphrase and paper shares.

Verdict:

- weak if some single place holds a whole k-subset ("one break-in at <place> opens it: <labels>"), or
  if a whole k-subset is 1Password shares of one account, which counts as one place ("one breach of the
  1Password account <account> opens it: <labels>"); the account is in the setup, so this applies with
  places unknown too.
- otherwise ok if some k-subset is papers only (they are spread over places, so a thief must find
  papers in two places).
- strong if every k-subset needs a YubiKey.

Each warning names the exact combination and suggests one fix (move a share elsewhere, raise k, or add
a share). The screen lists every opening combination:

```
Setup: 2 of 4   passphrase · YubiKey A · YubiKey B · paper

Loss    ✓ strong  you can lose any 2 shares
Theft   ⚠ weak    one break-in at home safe opens it: passphrase + YubiKey A
        → keep YubiKey A somewhere else, or use 3 of 4

All 6 combinations that open it:
  passphrase + YubiKey A      passphrase + YubiKey B      passphrase + paper
  YubiKey A + YubiKey B       YubiKey A + paper           YubiKey B + paper
```

If either verdict is weak, accepting needs the owner to type `yes`; otherwise Enter.

### The plan file (`setup.txt`)

Plain text, not secret, no places. It holds the same facts the public recovery sheet will hold. Example:

```
epn setup v1
k 2
share 1 passphrase "passphrase"
share 2 yubikey "YubiKey A"
share 3 yubikey "YubiKey B"
share 4 paper "paper"
share 5 1password "1Password A" account my.1password.com vault "Private"
```

Backup treats it as untrusted input: it re-validates everything (format limits, labels, account, vault).
The exact syntax is the builder's call as long as it is line-based, versioned and quote-safe for labels
and vault names with spaces.

### `vault backup [SETUP]`

`vault backup setup.txt` uses the plan. `vault backup` with no file runs the same setup, places and
scoring screens as `vault plan` inline (one code path), and saves nothing about places.

Steps (numbered on screen, "step i of N", N depends on the setup):

1. Output directory created and test-written (as today), setup loaded or chosen. With a plan file, show
   the setup and the place-free part of the scores (n - k loss, papers-only theft), with a note that
   places were checked in `vault plan`.
2. Offline checklist (as today), listing what to have ready: every YubiKey, paper and pen.
3. **Each YubiKey, one at a time**: "plug in only YubiKey B" (so `device_path` finds exactly one key;
   `--device` names one path, so a setup with more than one YubiKey refuses it before the output
   directory is made), then enroll a new credential or paste an existing credential id, then get its
   secret (PIN and touch). A missing key or wrong PIN fails here, before the seed is typed. Two shares
   must not use the same credential: refuse a repeated id. (Whether enrolment and secret share one PIN
   prompt is the builder's call.)

   **Each YubiKey share must be a different physical key** (owner's decision). Otherwise a missed swap,
   or a pasted credential id that is really on key A, puts two shares on one key while the self-check
   still passes and the scoring calls the setup strong. For every key after the first, list the
   credentials it holds for rpId `localhost` (`fido2-token -L -k localhost <device>`: its PIN, no touch)
   and refuse if any earlier share's credential id is on it: "this is the same key as YubiKey A; plug in
   YubiKey B". The cost is one extra PIN entry per extra key, which the owner accepted.
4. Seed, typed twice (as today).
5. Passphrase, if the setup has one: generated, shown, confirmed (as today).
6. Build: Argon2 once, pads for the passphrase and each YubiKey, `seal`, then **check every k-subset**
   opens the record and gives the seed. Save `record.hex` and `recovery-sheet.txt` (synced, as today)
   before any share is shown.
7. **Each paper and 1Password share, one at a time**: shown, written down, all 24 words typed back (as
   today). 1Password shares are shown for a TEMPORARY paper labelled for `vault op-store`, as today.
8. Done: fingerprint, record id, next steps: test restore, `vault op-store` per 1Password share,
   `publish`, write chain id and address on the sheet.

### Recovery sheet

One line per share, in share order, replacing the single `credential:` line and the `1password:` lines:

```
share 1:  passphrase   "passphrase"
share 2:  yubikey      "YubiKey A"   credential <id>   (rpId localhost)
share 3:  yubikey      "YubiKey B"   credential <id>   (rpId localhost)
share 4:  paper        "paper"
share 5:  1password    "1Password A" op://Private/epn-share-5-<record id>/password account my.1password.com
```

The rest of the sheet stays: record id, record, fingerprint, chain id/address blanks, how to read and
restore, the scripted `recover restore 0x.. --key 2=<id> --key 3=<id>` line with its stdin lines, and
"Any <k> of: <labels> restore the seed." No places.

The 1Password item title becomes `epn-share-<x>-<record id>` for that share's x (today x is fixed at 2,
`onepassword::X`). `vault op-store <sheet>` asks which 1Password share to store when the sheet names more
than one.

### `vault restore`

Reads the new share lines: label per share for prompts ("share 3: YubiKey B"), credential per YubiKey
share, 1Password reference per share. Still reads old sheets (one `credential:` line, `1password:`
lines) so every backup made so far restores as before. Asks to plug in one key at a time when several
YubiKey shares are held. Everything else (verify only, retries, unused-share notice) stays.

### Docs and tests

- README: the plan step, presets, scoring, several YubiKeys, the new sheet; remove the limitation
  "`vault backup` makes only the 2-of-3 layout".
- Unit tests: scoring (every rule above, including place cases), plan file round trip and rejection of
  bad files, sheet line parsing (new and old).
- `vault/tests/guided.rs` drives the interactive flow today; extend it for at least one 2-of-4 setup
  with two YubiKey shares if the test harness can fake keys, else the builder decides how far it can go.

## Left to the builder

- Module layout (for example a `layout.rs` for setups, presets, scoring and the plan file).
- Exact plan-file and sheet syntax within the rules above.
- Whether enrolment and getting the secret share one PIN/touch.
- How `guided.rs` covers several YubiKeys.
- Wording of prompts and warnings, in the style of the existing ones.
