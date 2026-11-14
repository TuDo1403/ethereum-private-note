# Ethereum Private Note

Back up a BIP39 wallet seed so that **any two of three factors** restore it, and **no single factor
reveals anything**:

| factor | what it is | where it lives |
|--------|------------|----------------|
| **passphrase** | 12 BIP39 words, generated for you (132 bits) | paper |
| **YubiKey** | FIDO2 `hmac-secret` of a resident credential, unlocked by the key's PIN and a touch | the key |
| **paper share** | 32 bytes written as 24 BIP39 words (looks like a seed, is not one) | paper |

The seed is encrypted with a random key, the key is split with Shamir, and the passphrase and YubiKey
shares are masked with pads derived from the passphrase and the YubiKey. The result is a 152-byte
**record** that is public by design: it can be stored on any EVM chain, emailed to yourself, printed, kept
in the cloud. Without two factors it is noise.

The format is k-of-n (2 <= k <= n <= 5; any number of hardware and paper shares, at most one passphrase share); `vault` makes
the 2-of-3 above. `SPEC.md` describes the format completely (enough to write a recovery tool in another
language) and `vectors.json` fixes every intermediate value.

> **Status.** Personal tool, not independently audited. The `publish` step has been tested against a
> local `anvil` chain only. Read [Limitations](#limitations) before trusting it with real funds.

---

## Contents

- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Install](#install)
- [Recommended setup](#recommended-setup)
- [Making a backup](#making-a-backup)
- [Publishing the record on chain](#publishing-the-record-on-chain)
- [Testing the backup](#testing-the-backup)
- [Restoring](#restoring)
- [Security considerations](#security-considerations)
- [Limitations](#limitations)
- [Development](#development)

---

## How it works

```
seed entropy ──AES-256-GCM(K)──► ciphertext ─┐
                                              │
K ──2-of-3 Shamir──► y1 ──xor pad1──► masked ─┤
                     y2 ──xor pad2──► masked ─┼──► record (152 bytes, public)
                     y3 ──────────────────────┼──► paper share (24 words, paper)
                                              │
pad1 = HKDF(Argon2id(passphrase, 1 GiB, t=3, salt), header)
pad2 = HKDF(YubiKey hmac-secret, header)
```

- **Passphrase + YubiKey**: both pads unmask both shares, two shares give K.
- **Passphrase + paper share** or **YubiKey + paper share**: one unmasked share plus the paper share give K.
- AES-GCM authenticates the result, so a wrong factor is reported, never silently accepted.

The record header (version, Argon2 cost, salt, k, n, share kinds) is the AES-GCM associated data and is mixed
into every pad, so each record has its own pads even though the YubiKey's secret is the same for every
record.

## Repository layout

| path | what |
|------|------|
| `core/` (`epn-core`) | the format: Argon2id, HKDF, GF(2^8) Shamir, AES-GCM, BIP39 words, FIDO2 via libfido2 |
| `vault/` (`vault`) | interactive wizard: **backup**, guided **restore**, and **op-store** (puts share 2 into 1Password) |
| `recover/` (`recover`) | small, scriptable **restore-only** tool; the one to keep for emergencies |
| `publish/` (`publish`) | online step: deploys the record as contract code from a throwaway gas key ([details](publish/README.md)) |
| `SPEC.md`, `vectors.json` | the backup format, and fixed test vectors for it |
| `vendor/` | every Rust dependency, pinned and vendored, so this builds offline years from now |

## Install

Requirements:

- **Rust 1.100** (the tested toolchain; edition 2024).
- **libfido2 command-line tools** (`fido2-token`, `fido2-cred`, `fido2-assert`), needed whenever the
  YubiKey is used:
  - macOS: `brew install libfido2`
  - Debian/Ubuntu: `apt install fido2-tools`
- **Foundry** (optional): `cast` to read the record back from a chain, `anvil` for tests.
- On Linux, `publish` uses the system OpenSSL for https RPCs.

Build all three binaries from the vendored sources, no network needed:

```bash
cargo build --release --offline --locked
```

The binaries are `target/release/vault`, `target/release/recover` and `target/release/publish`.
Build on a trusted machine and copy them, together with this repository (or at least `SPEC.md`), to
the offline machine you will use.

## Recommended setup

### What you need

- **An offline machine.** Best: a laptop booted from a live OS (for example Tails) with networking
  disabled and no persistent storage. Acceptable: a machine you trust with wifi off and the cable
  unplugged for the whole session. It needs 2 GiB of free RAM (Argon2id uses 1 GiB).
- **A YubiKey 5 (or any FIDO2 key with `hmac-secret`) with a FIDO2 PIN set.** Set the PIN first, for
  example with `ykman fido access change-pin`. Without a PIN the key cannot be used.
  **Or 1Password with Touch ID** instead of the YubiKey: share 2 is then kept as a 1Password item and
  read back with Touch ID. Install the `op` command and turn on *Settings > Developer > Integrate with
  1Password CLI* in the 1Password app. This is a weaker factor than a YubiKey: the share syncs with
  your 1Password account and is as safe as that account, not tied to one device. Use a **personal**
  account, never a work one (its admins can reach it, and you lose it with the job); `vault` asks for
  the account explicitly and passes it to every `op` call. **Never keep the passphrase or the paper
  share in that same account**, or one breach of it gives two factors. The `op` command needs
  1Password's servers, so the offline backup never runs it: share 2 goes on a temporary paper and is
  put into 1Password afterwards, on your online machine, with `vault op-store`.
- **Paper and a pen** for the passphrase and the paper share. Steel plates if you want fire/water resistance.
- **An online machine** for `publish` (later, no secrets involved).
- **A wallet with a little ETH** on the chain you choose, to fund the throwaway publishing address.

### Where to keep things

The rule: **no single place holds two factors.** A suggested layout:

| place | keeps |
|-------|-------|
| home safe | passphrase paper |
| on you / your desk | YubiKey (its PIN in your head or your password manager, never on the key), or share 2 in 1Password |
| second location (bank box, trusted family) | paper share, labelled *"backup share 3, not a wallet"* |
| anywhere, several copies | recovery sheet, `record.hex`, a printout of `SPEC.md` |

Losing one factor is survivable: the other two still restore. Restore at once and make a new backup,
because you are now one loss away from losing the seed.

### Choosing a chain

The chain is one durable copy of the public record, not the only one. Pick one you expect to be
alive and readable for decades, with cheap storage of ~150 bytes. Any EVM chain works: the record is
stored as the code of a new contract, so nothing needs to be deployed on the chain beforehand.

## Making a backup

On the **offline** machine, with the YubiKey plugged in:

```bash
./vault backup                  # or just ./vault and pick "Make a new backup"
./vault backup --device PATH    # when several FIDO2 keys are plugged in (see `fido2-token -L`)
./vault backup --allow-unsafe-host   # only if you accept the host check's findings (see "The machine you use")
```

`vault` refuses to run through a pipe; it needs a real terminal. Before asking for anything it creates
the output folder `./backup-<timestamp>/` and checks that it can write there. Then it walks through six
steps:

1. **Second factor.** Pick YubiKey (arrow keys, Enter), then press Enter to create a new resident credential (PIN,
   then touch), or paste the credential id of one made earlier by `vault`. The id is not secret; it goes
   on the recovery sheet. Or pick 1Password (Touch ID) and name the personal account (sign-in
   address or email, see `op account list`) and a vault in it (see `op vault list --account <account>`).
   Nothing is sent to 1Password during the backup: the sheet names the item `epn-share-2-<record id>`
   that `vault op-store` creates later (see *Putting share 2 into 1Password*), and `vault restore`
   offers to read it from there instead of typing it.
2. **Seed.** Type your 12–24 seed words (hidden), then type them again: both entries must give the same
   seed, because a typo that is another BIP39 word passes the checksum surprisingly often (1 in 16 for
   12 words). The **seed fingerprint** (8 hex digits, see `SPEC.md`) is shown; note it. Only the entropy
   is stored; your BIP39 passphrase ("25th word"), if you use one, is **not** part of the backup.
3. **Passphrase.** Twelve words are generated and shown once. Write them down in lowercase, one space
   between words. The screen is cleared and you must type them back.
4. **Build, check and save.** PIN and touch again (YubiKey only), then Argon2id (1 GiB, takes a while). Every pair of
   factors is tried against the new record; if any pair fails, nothing is saved. Then the two public
   files, `record.hex` and `recovery-sheet.txt`, are written (and synced to disk) **before** the paper
   share is shown, so a crash later cannot leave you with papers and no record. If writing fails, `vault`
   says so: destroy the papers of that run and start again.
5. **Paper share.** 24 words are shown once. Write them on a *separate* paper and label it *"backup
   share 3, not a wallet"*. Then type all 24 back (hidden); a mismatch shows the share again so you can
   correct the paper. With 1Password, share 2 is shown the same way next: write it on a **temporary**
   paper labelled *"share 2, for 1Password, destroy after `vault op-store`"*, kept apart from the
   other two papers (any two of the three restore the seed), and type it back.
6. **Next steps** are printed: test the papers with a verify-only restore, publish the record, fill in
   the recovery sheet.

The recovery sheet holds the record id, the record, the seed fingerprint, the credential id (or the
1Password reference) and blanks
for the chain id and the record's address. Print it, together with `SPEC.md`, and keep a copy of it (or
of `record.hex` and these locators) in the storage place of every factor paper too.

Then clear the terminal scrollback, and shut down the offline machine (or reboot the live OS).

### Putting share 2 into 1Password

Only with the 1Password option, after the papers are tested (see *Testing the backup*). On your
**online** machine with the 1Password app, never the machine that saw the seed:

```bash
./vault op-store backup-<timestamp>/recovery-sheet.txt
```

It reads the account and item name from the sheet (public), asks for share 2 from the temporary paper,
twice, and stores it (through stdin, never the command line or a file); 1Password asks for Touch ID.
Before storing it checks that the item does not exist yet; that check fails when the item is missing, but
also when 1Password is locked or offline, so it asks you to confirm in the 1Password app that the item is
absent. It then reads the item back and compares. Running it again finds the item instead of making a
duplicate. Then **destroy the temporary paper** (shred or burn it). Only share 2 is ever typed on this
machine.

## Publishing the record on chain

On the **online** machine, copy only `record.hex` across (USB stick, QR, or retype it: it is public).
`vault` prints the command for it. `publish` pays from a throwaway key so the sending address is never
tied to your seed, and it sweeps leftover ETH back.

```bash
./publish [--verify-rpc URL] [--confirmations N] [--allow-high-fees] <rpc-url> <record.hex> <refund-address>
```

Missing arguments are prompted for. What happens:

1. A throwaway key is created **in memory only**; its address and an `ethereum:<address>@<chain id>?value=<wei>`
   URI are printed. Send that amount from your wallet (check the chain id in the wallet). It waits 15 min.
2. The record is deployed as the code of a new contract and read back.
3. Leftover ETH is swept to the refund address, on every exit after funding, including failures.
4. Chain id, the record's address and the record id are printed. **Write chain id and address on the
   recovery sheet** (the record id must match the sheet's).

Recommended flags:

- `--verify-rpc <url>`: read the record back from a second, independent node, so one lying RPC cannot
  claim a store that did not happen.
- `--confirmations <n>` (default 1): wait for more blocks before the read-back.

The refund address must start with `0x`, have a valid checksum if mixed-case, and be an EOA (no code), not the zero address.
Fee quotes over 500 gwei/gas or 0.5 ETH total are refused without `--allow-high-fees`. See
[`publish/README.md`](publish/README.md) for the full safety behaviour.

Afterwards, check from a node you trust:

```bash
cast code <address> --rpc-url <rpc>
```

The output must be `0x00` followed by the contents of `record.hex` (without its `0x`).

## Testing the backup

**Do not trust a backup you have not restored.** On the offline machine, right after making it, run
`vault restore`, pick **Verify only** (the first, default item), and restore with each of the three pairs:

1. passphrase + YubiKey
2. passphrase + paper share
3. YubiKey + paper share

With 1Password, share 2 is still on its temporary paper at this point: answer **no** when `vault`
offers to read it from 1Password (that needs the network) and type the paper.

Verify only prints the seed fingerprint instead of the seed, so a test never puts your seed on screen.
It must equal the fingerprint on the recovery sheet. `vault` already checked all three pairs against
the in-memory values; this test checks what you actually **wrote on paper**.

Repeat a test every year or so, and whenever you move a factor, to find a smudged paper or a dead
YubiKey while you still have the other two.

## Restoring

You need the record (from the sheet, `record.hex`, or the chain) and any two factors. Do it offline:
the seed is printed on screen. Reading share 2 from 1Password needs the network, so offline, open the
item in the 1Password app on another device and type its 24 words when `vault` asks.

### Guided: `vault restore`

```bash
./vault restore [--device PATH] [--allow-unsafe-host]
```

Pick **Verify only** (seed fingerprint, never the seed; the default) or **Restore** (shows the seed) with
the arrow keys and Enter. Paste the record
hex, or give the path to `record.hex` (a `recovery-sheet.txt` beside it supplies the YubiKey credential
id, or the 1Password item of share 2). Say which factors you have; the YubiKey is asked first so a
missing key or wrong PIN fails before you type anything. A share kept in 1Password is offered from
1Password (Touch ID); if that read fails, you are asked to type the paper instead. The paper share is
entered word by word, the passphrase hidden. Three attempts. Verify only also lists any share you
held that was not needed, since any pair opens the record: test such a share in another run. This is
the normal way to restore: every secret is read at a hidden prompt.

### Scripted: `recover restore`

`recover` is deliberately small and reads secrets **only from stdin**, never from arguments, so they do
not land in `ps`. Run it alone, then type one factor per line and end with Ctrl-D:

```bash
./recover restore <record-hex> [--key X=CRED_ID]... [--device PATH] [--allow-unsafe-host]
```

```
pass <passphrase>        the passphrase: everything after the first space, not trimmed
paper <X> <24 words>     the paper share printed as share X
hw <X> <64 hex digits>   a hardware secret, instead of --key
```

`--key X=CRED_ID` asks the YubiKey that is share X for its secret (PIN and touch). For a backup made by
`vault`, the YubiKey (or the 1Password share, typed as `paper 2 ...`) is share 2 and the paper share is
share 3; the recovery sheet prints the exact command. Input is visible on screen, so mind the screen, but it never reaches shell history. **Never type
a factor into the command line itself**: your shell saves the whole line in its history file.

The seed words go to stdout, the shares used to stderr. Exit code 0 is success, 1 is a failed restore,
2 is a usage error. Errors never echo what you typed; a bad word is reported by its position or line.
See `SPEC.md` ("Restoring") for the exact rules.

If the recovery sheet is lost, the credential id can be listed from the key with its PIN:

```bash
fido2-token -L -k localhost <device>
```

### Without these tools

`SPEC.md` plus `vectors.json` are enough to rebuild the restore in any language. The building blocks
are standard: Argon2id, HKDF-SHA256, AES-256-GCM, Shamir over GF(2^8), BIP39. The YubiKey secret is the
same value a browser's WebAuthn PRF extension returns for rpId `localhost` and input `"bk1"`.

---

## Security considerations

### What each factor gives an attacker

| attacker holds | result |
|----------------|--------|
| the record only | nothing: masked or missing shares |
| record + any **one** factor | nothing about the seed, **but** see passphrase guessing below |
| record + any **two** factors | the seed |

The record is public, permanent and readable by anyone, forever. All confidentiality comes from the
factors.

### The passphrase is the weakest link, so it is generated

Anyone with the record and **one** of the paper share or the YubiKey (with its PIN) can test passphrase
guesses offline, for as long as they like. That is why the passphrase is generated (12 random words,
132 bits) and stretched with Argon2id at 1 GiB and 3 passes: brute force is far out of reach, even for a
quantum computer (Grover's search at best halves the bits, to about 66). Backups made with the older
7-word passphrase still restore. Do not
replace it with something you chose, and do not shorten it.

### A leaked factor cannot be revoked

The on-chain record is write-once and can never be deleted, and copies may exist anywhere. If any
single factor is exposed (paper photographed, YubiKey stolen together with its PIN, paper share seen),
making a new backup does **not** help, because the old record stays attackable with that factor.
**Move the funds to a new seed**, then back up the new seed.

### YubiKey

- Its PIN is the only thing between a thief of the key and its factor. Never store the PIN with the key.
  FIDO2 locks the key after repeated wrong PINs.
- The credential is tied to that physical key. It cannot be copied to a second YubiKey; a spare key
  does not replace a lost one (the other two factors do).
- **Never reset the FIDO2 application** on the key (`ykman fido reset`): that destroys the credential,
  and its factor with it.
- The credential uses rpId `localhost`. Software on any machine the key is plugged into that can make
  you enter the PIN and touch the key can obtain the secret. Only enter the PIN and touch the key when
  `vault` or `recover` asks, on a machine you trust.

### The paper share looks like a wallet seed

It is 24 valid BIP39 words. Someone who finds it may import it as a wallet (it will be empty) and move
on, which is harmless, but you might also mistake it for your seed. Label it. Store it apart from the
passphrase and the YubiKey.

### The machine you use

No software here can beat a keylogger, a screen recorder or a kernel-level endpoint agent (CrowdStrike,
SentinelOne, Carbon Black and the like): whoever owns the kernel sees every key you type, the screen and
process memory. `vault` and `recover` therefore do two modest, heuristic things, and the rest is where you run them:

- **Host check.** They refuse to start while a network interface is up (loopback and link-local do not
  count) or a known monitoring agent is installed, and say which. `--allow-unsafe-host` continues anyway,
  with the findings printed as a warning. The agent list is a few install paths: finding nothing proves
  nothing. `vault op-store` is exempt (it is the online step and only types share 2).
- **Process hardening.** No core dumps; other processes of the same user cannot attach a debugger or read
  the process (Linux `PR_SET_DUMPABLE`, macOS `PT_DENY_ATTACH`); on Linux all memory is locked out of swap
  when `RLIMIT_MEMLOCK` leaves room for Argon2's 1 GiB (run as root, or raise the limit). This stops crash
  collectors and same-user malware, **not root, and not an agent running in the kernel**. A failed step
  prints a warning.
- **Best fix: a machine that is never online and has no agent**: a spare laptop or a Raspberry Pi 4/5 booted
  from a read-only card, with no wifi. A managed work laptop is the wrong place for a seed.
- **Treat a real restore as burning the seed.** Prefer *Verify only*. If a restore showed the seed on a
  machine you do not fully trust, move the funds to a new seed afterwards.
- **Keep half the secret off the computer** if you sign with a hardware wallet: create the seed on the
  device and keep its own backup there, add a generated 12-word BIP39 passphrase (the "25th word") that you
  enter on the device's own screen, and back up *only that passphrase* with `vault` (as if it were a seed).
  A fully compromised computer then learns a passphrase that is useless without the device or its backup.
  Check that your device accepts a passphrase that long on its screen before relying on this.
- `vault` and `recover` need no network. Run backups and restores **offline**: the seed and secrets
  pass through memory and the screen.
- `vault` wipes seed, passphrase and key material from its memory after use (`zeroize`, best effort:
  copies made inside the format crate are not wiped), and the OS may still have paged memory to disk. A live OS without swap, or a machine with encrypted swap and
  hibernation off, avoids leaving copies on disk.
- Keep secrets out of anything that records the terminal: scrollback, screen recording, tmux logs,
  shell history, clipboard managers, screenshots syncing to the cloud. Clear the terminal afterwards.
- Never put secrets in a command line (as arguments, or inside a `printf ... | recover` pipeline) or
  `export` them in a shell whose history is saved. `recover` takes them on stdin for this reason; or use
  `vault restore`.
- Build from this repository's vendored sources (`--offline --locked`) on a machine you trust, and
  check you are running the binary you built.

### On-chain privacy

The record reveals that an address holds an Ethereum Private Note backup, the threshold and how many
shares exist. The throwaway sender holds nothing and is not derived from your seed, but **the
transaction that funds it links it to your wallet**, and the sweep links it to the refund address. If
you do not want your identity associated with a backup record, fund it from an address that is not
tied to you.

### The RPC node

`publish` sends only public data and transactions signed by the throwaway key, so an RPC cannot steal
a secret. It can censor or delay, quote inflated fees (bounded by the fee caps), or claim a store
succeeded when it did not. Use `--verify-rpc` with an independent node, and always re-check the record
with `cast code` against a node you trust before relying on it.

### Long-term recoverability

- Keep the record in several places besides the chain: the recovery sheet, email, cloud storage, and
  with each factor paper. Reading it from the chain needs the chain id and the record's address, which
  no factor can regenerate.
- Keep `SPEC.md` printed with the paper share, and keep a copy of this repository (with `vendor/`)
  somewhere durable. `recover` builds offline from it.
- The record carries a version byte; a future format must change it. Records of the earlier version 1
  are not read by these tools; the git tag `v1-final` holds the last tools that did.

## Limitations

- **Not independently audited.** Treat it as such.
- **`publish` has not been run against a real network yet**, only a local `anvil` chain. Do a full
  test run on a testnet before mainnet. Legacy (non-EIP-1559) chains are unsupported.
- `vault backup` makes only the 2-of-3 layout with one YubiKey. Other k-of-n layouts are in the format
  and are restored by `recover` and `vault restore`, but nothing here creates them.
- `recover` does not wipe secrets from memory after use (`vault` does).

## Development

```bash
cargo test --offline --locked     # unit, format vectors, CLI, and anvil end-to-end tests
cargo fmt --all --check
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
cargo deny check                  # advisories, licences, sources (https://github.com/EmbarkStudios/cargo-deny)
```

CI (`.github/workflows/ci.yml`) runs these on Linux and macOS, x86_64 and aarch64, and also checks
that `vendor/` is exactly what `cargo vendor` produces from `Cargo.lock`. The toolchain is pinned in
`rust-toolchain.toml`. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org)
(`type(scope): subject`, scopes in `.commitlintrc.yml`); the PR check enforces it. Pushing a tag
`vX.Y.Z` runs `release.yml`, which publishes the binaries with checksums and build provenance.

The test profile builds with `opt-level = 3` because the real-parameter vector runs Argon2id at
1 GiB. The anvil tests in `publish/` skip if `anvil` is not installed; the `vault` test skips if
`expect` is not installed.
