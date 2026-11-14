# Ethereum Private Note

Back up a BIP39 wallet seed so that **any two of three factors** restore it, and **no single factor
reveals anything**:

| factor | what it is | where it lives |
|--------|------------|----------------|
| **A** passphrase | 7 BIP39 words, generated for you (77 bits) | paper |
| **B** YubiKey | FIDO2 `hmac-secret` of a resident credential, unlocked by the key's PIN and a touch | the key |
| **C** share C | 32 bytes written as 24 BIP39 words (looks like a seed, is not one) | paper |

The seed is encrypted with a random key, the key is split 2-of-3 with Shamir, and shares A and B are
masked with pads derived from the passphrase and the YubiKey. The result is a 147-byte **record**
that is public by design: it can be stored on any EVM chain, emailed to yourself, printed, kept in the
cloud. Without two factors it is noise.

`SPEC.md` describes the format completely (enough to write a recovery tool in another language), and
`vectors.json` / `vectors-v2.json` fix every intermediate value.

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
K ──2-of-3 Shamir──► y1 ──xor padA──► encA ───┤
                     y2 ──xor padB──► encB ───┼──► record (147 bytes, public)
                     y3 ──────────────────────┼──► share C (24 words, paper)
                                              │
padA = HKDF(Argon2id(passphrase, 1 GiB, t=3, salt), header)
padB = HKDF(YubiKey hmac-secret, header)
```

- **Passphrase + YubiKey**: both pads unmask encA and encB, two shares give K.
- **Passphrase + share C** or **YubiKey + share C**: one unmasked share plus share C give K.
- AES-GCM authenticates the result, so a wrong factor is reported, never silently accepted.

The record header (Argon2 cost, salt) is the AES-GCM associated data and is mixed into both pads, so
each record has its own pads even though the YubiKey's secret is the same for every record.

## Repository layout

| path | what |
|------|------|
| `core/` (`epn-core`) | the format: Argon2id, HKDF, GF(2^8) Shamir, AES-GCM, BIP39 words, FIDO2 via libfido2 |
| `vault/` (`vault`) | interactive wizard: **backup** and guided **restore** (v1, 2-of-3) |
| `recover/` (`recover`) | small, scriptable **restore-only** tool for v1 and v2 records; the one to keep for emergencies |
| `publish/` (`publish`) | online step: stores a record in the `BlobStore` contract via a throwaway gas key ([details](publish/README.md)) |
| `src/BlobStore.sol` | write-once `mapping(address => bytes)`, no owner, no upgrades |
| `SPEC.md` | the backup format, v1 (2-of-3) and v2 (k-of-n) |
| `vendor/` | every Rust dependency, pinned and vendored, so this builds offline years from now |

## Install

Requirements:

- **Rust 1.94** (the tested toolchain; edition 2024).
- **libfido2 command-line tools** (`fido2-token`, `fido2-cred`, `fido2-assert`), needed whenever the
  YubiKey is used:
  - macOS: `brew install libfido2`
  - Debian/Ubuntu: `apt install fido2-tools`
- **Foundry** (optional): `cast` to read the record back from a chain, `forge`/`anvil` for tests.
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
- **Paper and a pen** for the passphrase and share C. Steel plates if you want fire/water resistance.
- **An online machine** for `publish` (later, no secrets involved).
- **A wallet with a little ETH** on the chain you choose, to fund the throwaway publishing address.

### Where to keep things

The rule: **no single place holds two factors.** A suggested layout:

| place | keeps |
|-------|-------|
| home safe | passphrase paper |
| on you / your desk | YubiKey (its PIN in your head or your password manager, never on the key) |
| second location (bank box, trusted family) | share C paper, labelled *"backup share, not a wallet"* |
| anywhere, several copies | recovery sheet, `record.hex`, a printout of `SPEC.md` |

Losing one factor is survivable: the other two still restore. Restore at once and make a new backup,
because you are now one loss away from losing the seed.

### Choosing a chain

The chain is one durable copy of the public record, not the only one. Pick one you expect to be
alive and readable for decades, with cheap storage of ~150 bytes. The contract address is the same on
every EVM chain that has the standard CREATE2 deployer (`0x4e59b448...b4956c`):

```
BlobStore: 0x0356F8a3FD7ef15B775896B63f822307547D8971
```

`publish` deploys it there if it is missing and refuses existing code there unless its hash matches.

## Making a backup

On the **offline** machine, with the YubiKey plugged in:

```bash
./vault backup                  # or just ./vault and pick 1
./vault backup --device PATH    # when several FIDO2 keys are plugged in (see `fido2-token -L`)
```

`vault` refuses to run through a pipe; it needs a real terminal. It walks through six steps:

1. **YubiKey.** Press Enter to create a new resident credential (PIN, then touch), or paste the
   credential id of one made earlier by `vault`. The id is not secret; it goes on the recovery sheet.
2. **Seed.** Type your 12–24 seed words (hidden). The BIP39 checksum is verified. Only the entropy is
   stored; your BIP39 passphrase ("25th word"), if you use one, is **not** part of the backup.
3. **Passphrase.** Seven words are generated and shown once. Write them down in lowercase, one space
   between words. The screen is cleared and you must type them back.
4. **Build and check.** PIN and touch again, then Argon2id (1 GiB, takes a while). Every pair of
   factors is tried against the new record; if any pair fails, nothing is saved.
5. **Share C.** 24 words are shown once. Write them on a *separate* paper and label it *"backup share,
   not a wallet"*. You are quizzed on three of them.
6. **Public files.** `./backup-<timestamp>/record.hex` and `./backup-<timestamp>/recovery-sheet.txt`
   are written. Both are public.

The recovery sheet holds the record, the credential id and blanks for chain id, contract and sender.
Print it, together with `SPEC.md`.

Then clear the terminal scrollback, and shut down the offline machine (or reboot the live OS).

## Publishing the record on chain

On the **online** machine, copy only `record.hex` across (USB stick, QR, or retype it: it is public).
Use `publish` rather than the `cast send` hint that `vault` prints: `publish` pays from a throwaway key
so the sender address is never tied to your seed, and it sweeps leftover ETH back.

```bash
./publish [--verify-rpc URL] [--confirmations N] [--allow-high-fees] <rpc-url> <record.hex> <refund-address>
```

Missing arguments are prompted for. What happens:

1. A throwaway key is created **in memory only**; its address and an `ethereum:<address>@<chain id>?value=<wei>`
   URI are printed. Send that amount from your wallet (check the chain id in the wallet). It waits 15 min.
2. `BlobStore` is deployed at the canonical address if needed, the record is stored and read back.
3. Leftover ETH is swept to the refund address, on every exit after funding, including failures.
4. Chain id, contract and sender are printed. **Write them on the recovery sheet.**

Recommended flags:

- `--verify-rpc <url>`: read the record back from a second, independent node, so one lying RPC cannot
  claim a store that did not happen.
- `--confirmations <n>` (default 1): wait for more blocks before the read-back.

The refund address must start with `0x`, have a valid checksum if mixed-case, and be an EOA (no code).
Fee quotes over 500 gwei/gas or 0.5 ETH total are refused without `--allow-high-fees`. See
[`publish/README.md`](publish/README.md) for the full safety behaviour and how to reproduce the
contract bytecode.

Afterwards, check from a node you trust:

```bash
cast call 0x0356F8a3FD7ef15B775896B63f822307547D8971 "records(address)(bytes)" <sender> --rpc-url <rpc>
```

The output must equal the contents of `record.hex`.

## Testing the backup

**Do not trust a backup you have not restored.** On the offline machine, right after making it,
restore with each of the three pairs:

1. passphrase + YubiKey
2. passphrase + share C
3. YubiKey + share C

`vault` already checked all three pairs against the in-memory values; this test checks what you
actually **wrote on paper**. Compare the restored words to your seed, then clear the screen.

Repeat a test every year or so, and whenever you move a factor, to find a smudged paper or a dead
YubiKey while you still have the other two.

## Restoring

You need the record (from the sheet, `record.hex`, or the chain) and any two factors. Do it offline:
the seed is printed on screen.

### Guided: `vault restore`

```bash
./vault restore [--device PATH]
```

Paste the record hex, or give the path to `record.hex` (a `recovery-sheet.txt` beside it supplies
the credential id). Say which factors you have; the YubiKey is asked first so a missing key or wrong
PIN fails before you type anything. Share C is entered word by word, the passphrase hidden. Three
attempts.

### Scripted: `recover restore` (v1)

`recover` is deliberately tiny and reads secrets **only from stdin**, never from arguments, so they do
not land in shell history or `ps`.

```bash
./recover restore <record-hex> [--cred-id ID [--device PATH]]
```

stdin line 1 is share C (24 words, or empty), the rest is the passphrase (or empty). Pass `--cred-id`
to use the YubiKey. For example, typing interactively (input is visible, so mind the screen):

```bash
./recover restore 0x01... --cred-id <credential-id>
```

then type the share C words, Enter, leave the passphrase line empty, Enter, and Ctrl-D. Exactly one
trailing newline is stripped from the passphrase; nothing else is trimmed.

The seed words go to stdout, the factors used to stderr. Exit code 0 is success, 1 is a failed
restore, 2 is a usage error. Errors never echo what you typed.

If the recovery sheet is lost, the credential id can be listed from the key with its PIN:

```bash
fido2-token -L -k localhost <device>
```

### v2 (k-of-n) records

Records whose first byte is `02` are restored with:

```bash
./recover restore <record-hex> [--key X=CRED_ID]... [--device PATH] < factors
```

with one factor per line in `factors` (or typed on stdin):

```
pass <passphrase>        the passphrase: everything after the first space, not trimmed
paper <X> <24 words>     the paper share printed as share X
hw <X> <64 hex digits>   a hardware secret, instead of --key
```

See `SPEC.md` ("`recover restore` for v2") for the exact rules.

### Without these tools

`SPEC.md` plus `vectors.json` are enough to rebuild the restore in any language. The building blocks
are standard: Argon2id, HKDF-SHA256, AES-256-GCM, Shamir over GF(2^8), BIP39. The YubiKey secret is the
same value a browser's WebAuthn PRF extension returns for rpId `localhost` and input `"bk1"`.

---

## Security considerations

### What each factor gives an attacker

| attacker holds | result |
|----------------|--------|
| the record only | nothing: three uniformly masked or missing shares |
| record + any **one** factor | nothing about the seed, **but** see passphrase guessing below |
| record + any **two** factors | the seed |

The record is public, permanent and readable by anyone, forever. All confidentiality comes from the
factors.

### The passphrase is the weakest link, so it is generated

Anyone with the record and **one** of share C or the YubiKey (with its PIN) can test passphrase guesses
offline, for as long as they like. That is why the passphrase is generated (7 random words, 77 bits)
and stretched with Argon2id at 1 GiB and 3 passes: brute force is far out of reach. Do not replace it
with something you chose, and do not shorten it.

### A leaked factor cannot be revoked

The on-chain record is write-once and can never be deleted, and copies may exist anywhere. If any
single factor is exposed (paper photographed, YubiKey stolen together with its PIN, share C seen),
making a new backup does **not** help, because the old record stays attackable with that factor.
**Move the funds to a new seed**, then back up the new seed.

### YubiKey

- Its PIN is the only thing between a thief of the key and factor B. Never store the PIN with the key.
  FIDO2 locks the key after repeated wrong PINs.
- The credential is tied to that physical key. It cannot be copied to a second YubiKey; a spare key
  does not replace a lost one (the other two factors do).
- **Never reset the FIDO2 application** on the key (`ykman fido reset`): that destroys the credential,
  and factor B with it.
- The credential uses rpId `localhost`. Software on any machine the key is plugged into that can make
  you enter the PIN and touch the key can obtain the secret. Only enter the PIN and touch the key when
  `vault` or `recover` asks, on a machine you trust.

### Share C looks like a wallet seed

It is 24 valid BIP39 words. Someone who finds it may import it as a wallet (it will be empty) and move
on, which is harmless, but you might also mistake it for your seed. Label it. Store it apart from the
passphrase and the YubiKey.

### The machine you use

- `vault` and `recover` need no network. Run backups and restores **offline**: the seed and secrets
  pass through memory and the screen.
- `vault` wipes seed, passphrase and key material from its memory after use (`zeroize`), but the OS
  may still have paged memory to disk. A live OS without swap, or a machine with encrypted swap and
  hibernation off, avoids leaving copies on disk.
- Keep secrets out of anything that records the terminal: scrollback, screen recording, tmux logs,
  shell history, clipboard managers, screenshots syncing to the cloud. Clear the terminal afterwards.
- Never pass secrets as command-line arguments or `export` them in a shell whose history is saved.
  `recover` takes them on stdin for this reason.
- Build from this repository's vendored sources (`--offline --locked`) on a machine you trust, and
  check you are running the binary you built.

### On-chain privacy

The record reveals that an address holds an Ethereum Private Note backup, its format version, and for
v2 the threshold and how many shares exist. The throwaway sender holds nothing and is not derived from
your seed, but **the transaction that funds it links it to your wallet**, and the sweep links it to
the refund address. If you do not want your identity associated with a backup record, fund it from an
address that is not tied to you.

### The RPC node

`publish` sends only public data and transactions signed by the throwaway key, so an RPC cannot steal
a secret. It can censor or delay, quote inflated fees (bounded by the fee caps), or claim a store
succeeded when it did not. Use `--verify-rpc` with an independent node, and always re-check the record
with `cast call` against a node you trust before relying on it.

### Long-term recoverability

- Keep the record in several places besides the chain: the recovery sheet, email, cloud storage.
  Reading it from the chain needs chain id, contract and sender, which no factor can regenerate.
- Keep `SPEC.md` printed with share C, and keep a copy of this repository (with `vendor/`) somewhere
  durable. `recover` builds offline from it.
- v1 records stay valid forever; a future format must change the version byte.

## Limitations

- **Not independently audited.** Treat it as such.
- **`publish` has not been run against a real network yet**, only a local `anvil` chain. Do a full
  test run on a testnet before mainnet. Legacy (non-EIP-1559) chains are unsupported.
- **Backups are v1 (2-of-3) only.** The v2 k-of-n format is specified and `recover` restores it, but no
  tool creates v2 records yet, and `publish` accepts only 147-byte v1 records.
- `vault` prints a `cast send` hint for publishing; prefer `publish`, which uses a throwaway sender.
- `recover` does not wipe secrets from memory after use (`vault` does).
- One YubiKey per v1 backup; a v1 backup has no second hardware factor.

## Development

```bash
cargo test --offline --locked     # unit, format vectors, CLI, and anvil end-to-end tests
forge test                        # BlobStore contract tests
```

The test profile builds with `opt-level = 3` because the real-parameter vector runs Argon2id at
1 GiB. The anvil tests in `publish/` skip if `anvil` is not installed.

The `BlobStore` bytecode, and therefore its address, is pinned by `foundry.toml` (solc 0.8.28, paris,
optimizer 200, no metadata). If the contract or compiler settings change, the canonical address
changes; see `publish/README.md` for how to regenerate and verify the constants.
