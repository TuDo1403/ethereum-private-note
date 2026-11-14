# Ethereum Private Note: backup format

Enough to reimplement recovery in any language. `vectors.json` holds fixed inputs and every intermediate
value; an implementation is correct if it reproduces them byte for byte. Print this with the paper share.

All integers big endian. Hex has no `0x` prefix. `||` is concatenation. The record carries a version byte
(`0x02`); any other version is refused. (An earlier fixed 2-of-3 layout, version `0x01`, is no longer
produced or read; the last tools that handled it are at the git tag `v1-final`.)

## Idea

A random AES-256 key `K` encrypts the seed. `K` is split k-of-n with Shamir, 2 <= k <= n <= 5; any k shares
give `K`, fewer give nothing. Each share has a kind that says where it lives:

| kind | byte | where the share lives | factor |
|------|------|------------------------|--------|
| passphrase | `01` | in the record, masked with a pad | generated passphrase through Argon2id |
| hardware | `02` | in the record, masked with a pad | 32-byte secret, e.g. YubiKey hmac-secret |
| paper | `03` | **not in the record** | the 32-byte share as 24 BIP39 words |

Share i (i = 1..n) is the share at x = i. At most one share is a passphrase share (a second one would be
the same secret under another pad). Any number of hardware and paper shares is allowed, and a record may
have no passphrase share or no on-chain share at all (all paper). A record that breaks these rules is
refused. `vault` makes any setup this allows: you choose the shares and k, and it numbers them in a fixed order,
the passphrase (if any) at x=1, then the YubiKeys, then the paper and 1Password shares. The recovery sheet
names every share with its x.

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

`header` = bytes 0..24+n. It is the AES-GCM associated data. The record is exactly
`85 + n + 32*c` bytes, c being the number of on-chain shares; any other length is invalid. 2-of-3
(passphrase, YubiKey, paper) is 152 bytes; 3-of-5 (passphrase, two YubiKeys, two paper) is 186; the
largest possible record is 250.

- Kinds may come in any order: a paper share may have a smaller x than on-chain shares, sit between them,
  or come last, and the passphrase share may be at any x. Masked shares are stored in increasing x with
  paper shares skipped, so a share's position among the masked shares is not its x. A share's masked
  bytes start at `24 + n + 32*(number of on-chain shares with a smaller x)`.
- k, n and every kind are in the AAD, and the pads depend on the header too, so changing any header byte
  (even to another valid value) makes decryption fail.
- Everything in the header is untrusted input: validate it (version, k/n range, kinds, one passphrase,
  exact length, and Argon2 cost) before spending seconds on Argon2. `m` must be 8 to 2^21 KiB (8 is
  Argon2's minimum for one lane; 2^21 is 2 GiB, twice the real 1 GiB) and `t` 1 to 16 (the real value
  is 3).

## Pads

- `argon` = Argon2id v1.3 (0x13), parallelism 1, `m`, `t`, salt from the header, 32-byte output,
  password = UTF-8 of the passphrase after Unicode NFKD normalization (no trimming).
- Pad of the on-chain share at x = HKDF(secret, info `"bk2/"` `||` ASCII digit of x `||` header), where
  secret is `argon` for the passphrase share and the 32-byte hardware secret for a hardware share. HKDF
  is HKDF-SHA256 with a salt of 32 zero bytes and a 32-byte output. x is the share's x from the header,
  never its index among the masked shares.
- (`bk2` names this format's pads; `bk1` in the hardware salt below is a historical name.) The label makes pads differ per share even if two secrets are equal; the header (with its random salt)
  makes them differ per record, which matters because a hardware secret is the same for every record.

## Shares

Per byte position, a polynomial of degree k-1 over GF(2^8) with the AES polynomial x^8+x^4+x^3+x+1
(0x11b): `f(x) = K + C1*x + C2*x^2 + ... + C(k-1)*x^(k-1)`, with C1..C(k-1) independent uniformly random
32-byte vectors. The share at x is `f(x)` (32 bytes). A masked share is `f(x) xor pad(x)`; a paper share is
`f(x)` itself.

Reconstruction from k shares (x_i, y_i), Lagrange interpolation at 0 (minus is xor in characteristic 2):
`K = xor over i of y_i * w_i`, with `w_i = product over j != i of x_j / (x_i xor x_j)`; division is
multiplication by `a^254`.

Sealing draws randomness in this order: K (32), C1 (32) .. C(k-1) (32), nonce (12). The test vectors
fix these bytes, which is how they reproduce the record exactly.

## Seed

`plaintext` = AES-256-GCM-decrypt(key = `K`, nonce, ct, AAD = `header`), 33 bytes: byte 0 is the entropy
length (16, 20, 24, 28 or 32), then the entropy zero-padded to 32 bytes. The padding **must** be zero: a
decoder refuses a plaintext whose length byte is not one of those five or whose padding bytes are not all
zero, even though it authenticated, so each seed has exactly one valid plaintext. The entropy is the
BIP39 entropy of the seed words (checksum words are recomputed, not stored). The BIP39 passphrase ("25th
word") is not part of this backup.

## Factors

- **Passphrase**: 7 random BIP39 words (77 bits), generated by `vault`, never chosen. It is the only
  low-entropy factor (see "Operating rules").
- **Hardware secret**: any reproducible 32-byte secret. The tools here use the FIDO2 hmac-secret of a
  resident credential with rpId `localhost`, with salt = SHA-256(`"WebAuthn PRF"` `||` 0x00 `||` `"bk1"`)
  (the salt a browser derives for WebAuthn PRF input `"bk1"`; the name is historical and kept so that
  existing credentials keep working). `vault` and `recover` get it through libfido2's command-line
  tools; the PIN and a touch are required. **User verification (the PIN) is part of the definition**:
  CTAP2 hmac-secret keeps two secrets per credential, one for assertions with user verification and one
  without, so the same key and salt give a different secret (and a useless factor) if UV is skipped.
  Always assert with UV. Each YubiKey has its own credential, and the x it was enrolled for is printed
  with its credential id.
- **Paper share**: 32 bytes as 24 BIP39 English words (standard entropy-to-words encoding, checksum
  included). It looks like a seed and is not one. Where it is kept is not part of the format: `vault`
  can keep a paper share (any x, and there may be several) in 1Password, as a Password item whose value is
  the 24 words, named `epn-share-<x>-<record id>` for that share's x and read with
  `op read --account <account> op://<vault>/<item>/password` (1Password asks for Touch ID). The recovery
  sheet names it on that share's line, which ends with
  `op://<vault>/<item>/password account <account>`; the account is always given, because with
  several accounts signed in `op` would otherwise pick one. (Sheets made before setups were flexible
  named only share 2, on a line `1password: share 2 op://<vault>/<item>/password account <account>`;
  `vault restore` still reads them.) Such a share must sit in a personal account, never a work one, and not
  in the same account as another factor of the record. `op` needs 1Password's servers, so `vault backup`
  (offline) only shows the share for a temporary paper; `vault op-store <sheet>` stores it later on an
  online machine that never holds another factor (it asks which share when the sheet names several).

Using a YubiKey also needs its credential id (base64, printed by `vault backup` and on the recovery
sheet). It is not secret and is useless without the key. If the sheet is lost it can be listed from the
key with its PIN: `fido2-token -L -k localhost <device>`.

## Test vectors

`vectors.json` is an array. Entries without an `error` field are valid records with every input and
intermediate value; they pin the layout rules above (paper share before the on-chain
ones, passphrase at x = 3, paper between on-chain shares, a hardware-only record, all paper). Entries with
an `error` field are records a decoder **must refuse**, given with the factors (`x`, and `value`: the pad
of an on-chain share or the paper share itself) that open the valid record they were made from:

| name | why it is refused |
|------|-------------------|
| `invalid-two-passphrase-shares` | two shares of kind 01 |
| `invalid-argon2-m-above-cap` | `m` = 2^21 + 1 KiB |
| `invalid-length-one-byte-extra` | one byte longer than its header allows |
| `invalid-nonzero-plaintext-padding` | authenticates, but a padding byte of the plaintext is not zero |

`error` is text the reference implementation's error message contains; another implementation only has
to refuse.

## Restoring

Collect every factor you hold as a share (unmask on-chain shares with their pad). If you hold more than
k, try every k-subset until AES-GCM verifies, so a wrong factor among extras is harmless; with fewer than
k it is an error ("need at least k factors"), not a guess. Then decrypt as in "Seed".

Hardware and paper shares must be given with their x, printed next to each at backup time (the
passphrase's x is the one with kind 01, so it needs no label). A factor given at an x of the wrong kind
is refused.

The normal way is `vault restore`: it reads every secret at a hidden prompt on the terminal. `recover` is
the small scriptable tool:

    recover restore <record-hex> [--key X=CRED_ID[@PATH]]... [--device PATH]   < factors

`--key X=CRED_ID` (repeatable) asks the YubiKey that is share X for its secret through libfido2 (PIN and
touch); `--device` picks the device when several are plugged in. With two or more YubiKeys plugged in at
once, give each key its own device as `--key X=CRED_ID@PATH` (`fido2-token -L` lists the paths); a key
without `@PATH` uses `--device`, else the only key found. stdin holds one factor per line, in any
order, blank lines ignored:

    pass <passphrase>          the passphrase: everything after the first space, not trimmed
    paper <X> <24 words>       the paper share printed as share X
    hw <X> <64 hex digits>     a hardware secret as hex, instead of --key (a 0x prefix and capitals are fine)

Run the command alone and type the factor lines into its stdin, then Ctrl-D (they reach the program, not
shell history, but they are visible on screen), and **never put a factor inside a command line**: the
shell saves the whole line, secrets included, in its history file. A line is split at its first space, so
`pass` needs a space after it. The passphrase is exactly the rest of the line: nothing is trimmed (a
trailing space is part of the passphrase; the line's own newline, and a `\r` before it, is not). `pass `
followed by nothing means the passphrase is not held; it is never tried as the empty passphrase. At most
one `pass` line, and a passphrase cannot contain a newline.

The seed words are printed on stdout, the shares used on stderr. Secrets are only read from stdin, never
from arguments; an unexpected argument or a malformed stdin line gives a usage error (exit 2) that never
repeats what was typed, only the line number and the kind of factor (`invalid paper share`). Paper words
are checked (24 words, checksum) and every factor's x is checked before the YubiKey is asked for its PIN
and before Argon2 starts. Fewer than k factors, or too few correct ones, exit 1.

## On-chain storage

The record is the runtime code of a new contract, so it lives in state (not in a transaction's history,
which nodes may expire). The code is `0x00 || record`: the leading STOP byte keeps the data from ever
executing and keeps the code from starting with `0xEF`, which EIP-3541 rejects. The creation code is

    61 LLLL 80 60 0a 3d 39 3d f3 00 || record      (LLLL = 1 + record length, big endian)

i.e. PUSH2 len, DUP1, PUSH1 10, RETURNDATASIZE, CODECOPY, RETURNDATASIZE, RETURN, then the data. The
contract is created from a throwaway account at nonce 0, so its address is
`keccak256(rlp([sender, 0]))[12..]`. To read it back, call `eth_getCode(address)` (`cast code <address>`)
and drop the first byte. Nothing else is needed: no ABI, no deployed helper contract.

The address holds the record only if the deploy was the sender's nonce-0 transaction. `publish` sends the
deploy with nonce 0 and nothing else from that key except its sweep; if the sweep had to replace a stuck
deploy, the address stays empty. `publish` then reports the failure, and says the record is stored only
when it finds the record at the address. The largest record (250
bytes) gives 251 bytes of code, far below the EIP-170 limit of 24576.

## Where the record lives

The record is public by design, so keep copies anywhere: its hex printed with the paper share, email,
cloud. The chain is one durable copy, not the only one. Reading the chain copy needs two public values no
factor can regenerate: the chain id and the address of the contract whose code holds the record. Write
them on the recovery sheet after publishing, and keep a copy of the record (or the sheet) with these
locators in the storage place of every factor, so any k factors arrive with what they need.

## Short identifiers

- **record id** = the first 8 bytes of SHA-256 over the whole record, as 16 hex digits. A short name for
  one record; `vault` writes it on the recovery sheet and `publish` prints it after storing.
- **seed fingerprint** = the first 4 bytes of SHA-256 over the seed entropy (the bytes the plaintext
  carries, not the words), as 8 hex digits. `vault` shows it when the seed is entered, writes it on the
  recovery sheet, and a verify-only restore prints it instead of the seed. It does not reduce security
  meaningfully: it is 32 bits of a hash, so even a 128-bit seed keeps 96 bits that an attacker holding
  the fingerprint must still search. Its job is to catch a wrong seed (a typo that still passes the
  BIP39 checksum) without ever showing the seed.

## What the record shows

The record is public, and its length is `85 + n + 32*c`, with n and every kind in the clear header. It
therefore tells anyone the threshold k, how many shares there are and how many are on chain; it does not
tell which paper or YubiKey is where. An all-paper record (c = 0) is valid: nothing in it is masked.

## Operating rules

- The passphrase is generated by `vault backup`, never chosen. It is the only low-entropy factor, and the
  record is public: anyone holding enough other shares to be one factor short of k can test passphrase
  guesses against it offline, forever.
- The record is write-once and can never be deleted. If any factor leaks, a new backup does not help,
  because the old record stays attackable: move the funds to a new seed.
- Run `vault backup` on an offline machine. `vault` reads every secret from the terminal with echo off
  (hidden prompts) and shows the generated ones on the terminal, so keep it out of anything that records
  the terminal. The seed is typed twice and both entries must give the same entropy; the paper share is
  typed back in full (24 words) before the backup counts as made.
- Test the papers right after a backup with `vault restore`, option "verify only": it prints the seed
  fingerprint, never the seed, and must match the one on the recovery sheet.
- **Each hardware share must be a different physical YubiKey**: one key in two slots gives one factor
  twice, silently lowering the real threshold by one. Keep the YubiKey apart from the paper share (its PIN
  is the only thing between a thief of the key and its factor), and keep paper shares and YubiKeys in
  different places so that no single place holds k factors. With 3-of-5, two lost factors are survivable
  but any three held together restore.
