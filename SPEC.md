# Ethereum Private Note: backup format

# Format v1

Enough to reimplement recovery in any language. `vectors.json` holds fixed inputs and every intermediate
value; an implementation is correct if it reproduces them. Print this with share C.

All integers big endian. Hex has no `0x` prefix. `||` is concatenation.

## Record (147 bytes, stored as contract code: `0x00 || record`, read with `eth_getCode`)

| bytes   | field    | meaning                                                      |
|---------|----------|--------------------------------------------------------------|
| 0       | version  | `0x01`                                                       |
| 1..5    | m        | Argon2id memory in KiB (uint32)                              |
| 5       | t        | Argon2id iterations                                          |
| 6..22   | salt     | Argon2id salt                                                |
| 22..54  | encA     | share A masked with `padA`                                   |
| 54..86  | encB     | share B masked with `padB`                                   |
| 86..98  | nonce    | AES-GCM nonce                                                |
| 98..147 | ct       | AES-256-GCM ciphertext (33 bytes) then 16-byte tag           |

`header` = bytes 0..22. It is the AES-GCM associated data.

`m` and `t` are read from an untrusted record. Implementations should accept only `m` from 8 to 2^21 KiB
(8 is Argon2's minimum for one lane; 2^21 is 2 GiB, twice the real 1 GiB) and `t` from 1 to 16 (the real
value is 3), and refuse anything else before allocating or hashing.

## Factors

- **padA** = HKDF(`argon`, info `"bk1/A"` `||` header), where `argon` = Argon2id v1.3 (0x13), parallelism 1,
  `m`, `t`, salt from the record, 32-byte output, password = UTF-8 of the passphrase after Unicode NFKD
  normalization (no trimming).
- **padB** = HKDF(`prf`, info `"bk1/B"` `||` header), where `prf` is a 32-byte secret from the YubiKey: the
  CTAP2 hmac-secret output of a resident credential with rpId `localhost`, with salt =
  SHA-256(`"WebAuthn PRF"` `||` 0x00 `||` `"bk1"`) (the same salt a browser derives for WebAuthn PRF input
  `"bk1"`). `vault` and `recover` get it through libfido2's command-line tools; the PIN and a touch are
  required. **User verification (the PIN) is part of the definition**: CTAP2 hmac-secret keeps two
  secrets per credential, one for assertions with user verification and one without, so the same key
  and salt give a different `prf` (and a useless factor B) if UV is skipped. Always assert with UV.
  The record does not say where `prf` came from, so any reproducible 32-byte secret works the same way.
  Not needed when you hold the other two.
- **share C** = 32 bytes written as 24 BIP39 English words (standard entropy-to-words encoding).

HKDF is HKDF-SHA256 with a salt of 32 zero bytes, 32-byte output. The header (22 bytes, with the random
salt) is in the info so each record gets its own pads; the passkey's `prf` is the same for every record,
and without this a pad recovered from one record would unmask share B of all the others.

## Shares

2-of-3 Shamir over GF(2^8) with the AES polynomial x^8+x^4+x^3+x+1 (0x11b), byte by byte. With key `K`
and random line `L`, share at x is `y_x = K xor (L * x)`, with x = 1 (A), 2 (B), 3 (C).
`y_1 = encA xor padA`, `y_2 = encB xor padB`, `y_3` = share C.

From two shares (x1,y1), (x2,y2): `L = (y1 xor y2) / (x1 xor x2)`, then `K = y1 xor (L * x1)`
(division is multiplication by `a^254`).

## Seed

`plaintext` = AES-256-GCM-decrypt(key = `K`, nonce, ct, AAD = `header`), 33 bytes:
byte 0 is the entropy length (16, 20, 24, 28 or 32), then the entropy zero-padded to 32 bytes. The
padding **must** be zero: a decoder refuses a plaintext whose length byte is not one of those five or
whose padding bytes are not all zero, even though it authenticated, so each seed has exactly one valid
plaintext. This applies to v1 and v2.
The entropy is the BIP39 entropy of the seed words (checksum words are recomputed, not stored).
The BIP39 passphrase ("25th word") is not part of this backup.

## On-chain storage

The record is the runtime code of a new contract, so it lives in state (not in a transaction's history, which
nodes may expire). The code is `0x00 || record`: the leading STOP byte keeps the data from ever executing and
keeps the code from starting with `0xEF`, which EIP-3541 rejects. The creation code is

    61 LLLL 80 60 0a 3d 39 3d f3 00 || record      (LLLL = 1 + record length, big endian)

i.e. PUSH2 len, DUP1, PUSH1 10, RETURNDATASIZE, CODECOPY, RETURNDATASIZE, RETURN, then the data. The contract
is created from a throwaway account at nonce 0, so its address is `keccak256(rlp([sender, 0]))[12..]`. To read
it back, call `eth_getCode(address)` (`cast code <address>`) and drop the first byte. Nothing else is needed:
no ABI, no deployed helper contract.

The address holds the record only if the deploy was the sender's nonce-0 transaction. `publish` sends the
deploy with nonce 0 and nothing else from that key except its sweep; if the sweep had to replace a stuck
deploy, the address stays empty and `publish` reports that nothing was stored. The largest record (250 bytes)
gives 251 bytes of code, far below the EIP-170 limit of 24576.

## Where the record lives

The record is public by design, so keep copies anywhere: its hex printed with share C, email, cloud.
The chain is one durable copy, not the only one. Reading the chain copy needs three public values that
no factor can regenerate: the chain id and the address of the contract whose code holds the record
(see "On-chain storage"). Write them on the recovery sheet after publishing, and keep a copy of the
record (or the sheet) with these locators in the storage place of every factor, so any two factors
arrive with what they need.

Using the YubiKey also needs its credential id (base64, printed by `vault backup` and on the recovery
sheet). It is not secret and is useless without the key. If the sheet is lost it can be listed from the
key with its PIN: `fido2-token -L -k localhost <device>`.

## Short identifiers (both formats)

- **record id** = the first 8 bytes of SHA-256 over the whole record, as 16 hex digits. A short name
  for one record; `vault` writes it on the recovery sheet and `publish` prints it after storing.
- **seed fingerprint** = the first 4 bytes of SHA-256 over the seed entropy (the bytes the plaintext
  carries, not the words), as 8 hex digits. `vault` shows it when the seed is entered, writes it on the
  recovery sheet, and a verify-only restore prints it instead of the seed. It does not reduce security
  meaningfully: it is 32 bits of a hash, so even a 128-bit seed keeps 96 bits that an attacker holding
  the fingerprint must still search. Its job is to catch a wrong seed (a typo that still passes the
  BIP39 checksum) without ever showing the seed.

## Restoring with `recover` (v1)

The normal way is `vault restore`: it reads every secret at a hidden prompt on the terminal. `recover`
is the small scriptable tool; it reads secrets only from stdin (line 1 share C, the rest the passphrase;
either may be empty) and never from arguments:

    IFS= read -rs C; IFS= read -rs P; printf '%s\n%s' "$C" "$P" | recover restore <record-hex> [--cred-id ID [--device PATH]]; unset C P

then type share C, Enter, the passphrase, Enter; nothing is shown. **Never type a secret into the
command line itself** (for example `printf '%s\n%s' "word word ..." "pass" | recover ...`): the shell
saves the whole line, secrets included, in its history file. `read -rs` keeps them out of history and
off the screen, and `unset` drops them from the shell afterwards. Exactly one trailing `\n` or `\r\n` is
removed from the passphrase; nothing else is trimmed. Share C words and the number of factors are
checked before the YubiKey is asked for its PIN and before Argon2 starts. Errors name a word's position,
never its text.

## Operating rules

- The passphrase is generated by `vault backup` (7 random BIP39 words, 77 bits), never chosen. It is
  the only low-entropy factor: anyone holding share C or the YubiKey (and its PIN) can test passphrase
  guesses against the public record offline, forever.
- The record is write-once and can never be deleted. If any one factor leaks, a new backup does not
  help, because the old record stays attackable: move the funds to a new seed.
- Run `vault backup` on an offline machine. `vault` reads every secret from the terminal with echo off
  (hidden prompts) and shows the generated ones on the terminal, so keep it out of anything that records
  the terminal. The seed is typed twice and both entries must give the same entropy; share C is typed
  back in full (24 words) before the backup counts as made.
- Test the papers right after a backup with `vault restore`, option "verify only": it prints the seed
  fingerprint, never the seed, and must match the one on the recovery sheet.
- Keep the YubiKey apart from share C. Its PIN is the only thing between a thief of the key and factor B.

A future format must change the version byte. Version 2 is below; version 1 records stay valid forever.

# Format v2 (version byte `0x02`): k-of-n

Same primitives as v1 (Argon2id, HKDF-SHA256, GF(2^8) Shamir, AES-256-GCM, 33-byte padded plaintext,
the "Seed" section above), but the number of shares and what each one is are chosen at backup time:
2 <= k <= n <= 5, any k shares restore. `vectors-v2.json` holds fixed inputs and every intermediate value;
an implementation is correct if it reproduces them byte for byte. Same notation as v1.

## Share kinds

Share i (i = 1..n) is the share at x = i. Its kind is one byte in the header:

| kind | byte | where the share lives | factor |
|------|------|------------------------|--------|
| passphrase | `01` | on chain, masked with a pad | generated passphrase through Argon2id |
| hardware | `02` | on chain, masked with a pad | 32-byte secret, e.g. YubiKey hmac-secret |
| paper | `03` | **not in the record** | the 32-byte share as 24 BIP39 words |

At most one share is a passphrase share (a second one would be the same secret under another pad).
Any number of hardware and paper shares is allowed. A record that breaks these rules is refused.

## Record

| bytes | field | meaning |
|-------|-------|---------|
| 0 | version | `0x02` |
| 1..5 | m | Argon2id memory in KiB (uint32) |
| 5 | t | Argon2id iterations |
| 6..22 | salt | Argon2id salt (16 bytes) |
| 22 | k | shares needed, 2..=n |
| 23 | n | shares in total, k..=5 |
| 24..24+n | kinds | kind byte of the share at x = 1, 2, .., n |
| 24+n.. | masked shares | 32 bytes for each on-chain (kind 01 or 02) share, **in increasing x**, none for paper |
| then 12 | nonce | AES-GCM nonce |
| then 49 | ct | AES-256-GCM ciphertext (33 bytes) then 16-byte tag |

`header` = bytes 0..24+n. It is the AES-GCM associated data. Length of a record is exactly
`24 + n + 32*c + 12 + 49 = 85 + n + 32*c` where c is the number of on-chain shares; any other length is
invalid. Presets: 2-of-3 (passphrase, YubiKey, paper) is 152 bytes; 3-of-5 (passphrase, two YubiKeys,
two paper) is 186 bytes. A share's masked bytes start at `24 + n + 32*(number of on-chain shares with a
smaller x)`.

Layout rules, all pinned by vectors:

- Kinds may come in any order: a paper share may have a smaller x than on-chain shares, sit between them,
  or come last, and the passphrase share may be at any x. Masked shares are stored in increasing x with
  paper shares simply skipped, so a share's position among the masked shares is not its x.
- A pad's label is the share's **x**, never its position among the masked shares (see "Pads").
- A record may have no passphrase share (hardware and paper only, or hardware only) or no on-chain
  share at all (all paper).

k, n and every kind are in the AAD, and the pads depend on the header too, so changing any header byte
(even to another valid value) makes decryption fail. Everything in the header is untrusted input:
validate it (version, k/n range, kinds, one passphrase, exact length) before spending seconds on Argon2.

## Pads

- `argon` = Argon2id exactly as for v1 padA (parallelism 1, v1.3, 32 bytes, password = UTF-8 of the
  passphrase after NFKD, no trimming) with `m`, `t`, salt from the header.
- Pad of the on-chain share at x = HKDF(secret, info `"bk2/"` `||` ASCII digit of x `||` header) (x is
  the share's x from the header, 1..n, not its index among the masked shares), where
  secret is `argon` for the passphrase share and the 32-byte hardware secret for a hardware share. HKDF
  is as in v1 (SHA-256, salt of 32 zero bytes, 32-byte output).
- The label makes pads differ per share even if two secrets are equal; the header (with its random salt)
  makes them differ per record, which matters because a hardware secret is the same for every record.
  The version in `bk2` keeps v1 and v2 pads apart.
- Hardware secret: any reproducible 32-byte secret. The tools here use the FIDO2 hmac-secret of a
  credential with rpId `localhost`, the salt of v1 and user verification required (see "Factors");
  each YubiKey has its own credential, and the x it was enrolled for is printed with its credential id.

## Shares

Per byte position, a polynomial of degree k-1 over GF(2^8) (AES polynomial 0x11b, as in v1):
`f(x) = K + C1*x + C2*x^2 + ... + C(k-1)*x^(k-1)`, with K the AES key and C1..C(k-1) independent
uniformly random 32-byte vectors. The share at x is `f(x)` (32 bytes). Because x = 1..n is distinct and
nonzero and any k points determine a degree k-1 polynomial, any k shares give K and fewer give nothing.
A masked share is `f(x) xor pad(x)`; a paper share is `f(x)` itself.

Reconstruction from k shares (x_i, y_i), Lagrange interpolation at 0 (minus is xor in characteristic 2):
`K = xor over i of y_i * w_i`, with `w_i = product over j != i of x_j / (x_i xor x_j)`; division is
multiplication by `a^254`. With k = 2 this is the v1 formula.

Sealing draws randomness in this order: K (32), C1 (32) .. C(k-1) (32), nonce (12). The test vectors
fix these bytes, which is how they reproduce the record exactly.

## Test vectors

`vectors-v2.json` is an array. Entries without an `error` field are valid records with every input and
intermediate value; besides the presets they pin the layout rules above (paper share before the
on-chain ones, passphrase at x = 3, paper between on-chain shares, a hardware-only record). Entries with
an `error` field are records a decoder **must refuse**, given with the factors (`x`, and `value`: the pad
of an on-chain share or the paper share itself) that open the valid record they were made from:

| name | why it is refused |
|------|-------------------|
| `invalid-two-passphrase-shares` | two shares of kind 01 |
| `invalid-argon2-m-above-cap` | `m` = 2^21 + 1 KiB |
| `invalid-length-one-byte-extra` | one byte longer than its header allows |
| `invalid-nonzero-plaintext-padding` | authenticates, but a padding byte of the plaintext is not zero |

`error` is text the reference implementation's error message contains; another implementation only
has to refuse.

## Restoring

Collect every factor you hold as a share (unmask on-chain shares with their pad). If you hold more than
k, try every k-subset until AES-GCM verifies, so a wrong factor among extras is harmless; with fewer than
k it is an error ("need at least k factors"), not a guess. Then decrypt as in "Seed" above, with the
header (24+n bytes) as AAD.

Argon2 cost bounds are the same as v1: `m` in 8..=2^21 KiB, `t` in 1..=16, checked while parsing the
header, before any other work.

Hardware and paper shares must be given with their x: it is printed next to each at backup time (the
passphrase's x is the one with kind 01, so it needs no label). A factor given at an x of the wrong kind
is refused.

## `recover restore` for v2

The tool picks the format from the record's first byte. v1 arguments and stdin are described in
"Restoring with `recover` (v1)" above. The same warning holds here: run the command alone and type the
factor lines into its stdin, then Ctrl-D (they reach the program, not shell history, but they are
visible on screen), and never put a factor inside a command line.

    recover restore <record-hex> [--key X=CRED_ID]... [--device PATH]   < factors

`--key X=CRED_ID` (repeatable) asks the YubiKey that is share X for its secret through libfido2 (PIN and
touch); `--device` picks the device when several are plugged in. stdin holds one factor per line, in any
order, blank lines ignored:

    pass <passphrase>          the passphrase: everything after the first space, not trimmed
    paper <X> <24 words>       the paper share printed as share X
    hw <X> <64 hex digits>     a hardware secret as hex, instead of --key

A line is split at its first space, so `pass` needs a space after it. The passphrase is exactly the rest
of the line: nothing is trimmed (a trailing space is part of the passphrase; the line's own newline, and
a `\r` before it only if the terminal adds one, is not), so type it as printed. `pass ` followed by
nothing means the passphrase is not held, like an empty line 2 in v1; it is never tried as the empty
passphrase. At most one `pass` line, and a passphrase cannot contain a newline. The seed
words are printed on stdout, the shares used on stderr. Secrets are only read from stdin, never from
arguments; an unexpected argument or a malformed stdin line gives a usage error (exit 2) that never
repeats what was typed, only the line number and the kind of factor (`invalid paper share`). Paper words
are checked (24 words, checksum) and every factor's x is checked before the YubiKey is asked for its PIN
and before Argon2 starts. `--cred-id` is a v1 option and is refused for v2. Fewer than k factors, or too few correct ones, exit 1.

## What the record shows

The record is public, and its length is `85 + n + 32*c`, with n and every kind in the clear header. It
therefore tells anyone the threshold k, how many shares there are and how many are on chain; it does not
tell which paper or YubiKey is where. An all-paper record (c = 0) is valid: nothing in it is masked.

## Operating rules for v2

The v1 rules apply. Beyond them: **each hardware share must be a different physical YubiKey** (enroll one credential per key and print its
x with its credential id): one key in two slots gives one factor twice, silently lowering the real
threshold by one. Keep paper shares and YubiKeys in different places so that no single
place holds k factors; with 3-of-5, two lost factors are survivable but any three held together restore.
The passphrase remains the only low-entropy factor and the record is public, so anyone holding enough
other shares to be one factor short of k can test passphrase guesses offline: that is why it is generated.
