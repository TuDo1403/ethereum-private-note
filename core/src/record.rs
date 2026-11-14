//! The record (see SPEC.md): k-of-n Shamir sharing of an AES key, 2 <= k <= n <= 5. Every share has a kind.
//! Passphrase and hardware shares are stored on chain, masked with a pad; paper shares are never in the
//! record. `tests/vectors.rs` rebuilds ../../vectors.json byte for byte.

use crate::bip39::{entropy_to_words, share_from_words};
use crate::shamir::{interpolate, poly_at};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;

const VERSION: u8 = 2;
const MAX_N: usize = 5;
/// 1 GiB, 3 passes. A restore needs this much free memory, so do not pick a number your recovery
/// machine cannot allocate.
pub const ARGON_M_KIB: u32 = 1 << 20;
pub const ARGON_T: u8 = 3;
// m and t come from the record, i.e. from untrusted input. 2 GiB is twice the real 1 GiB; each pass costs
// as much time as the whole 1 GiB hash, and the real t is 3. 16 leaves room to raise it later and still
// bounds the time a forged record can burn.
const MAX_M_KIB: u32 = 1 << 21;
const MAX_T: u8 = 16;
/// version, m, t, salt, k, n; the kinds follow, one byte per share.
const FIXED_HEADER: usize = 24;
/// nonce, then 33 bytes of padded plaintext and the 16-byte GCM tag.
const NONCE: usize = 12;
const CT: usize = 33 + 16;
/// (x, 32 bytes): a factor (the pad of an on-chain share, or a paper share), or a share once unmasked.
pub type Share = (u8, [u8; 32]);
const ENTROPY_LENGTHS: [usize; 5] = [16, 20, 24, 28, 32];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// On chain, masked with a pad from Argon2id of a generated passphrase.
    Passphrase = 1,
    /// On chain, masked with a pad from a 32-byte hardware secret (YubiKey hmac-secret).
    Hardware = 2,
    /// Off chain: the share itself is written down as 24 words and is not in the record.
    Paper = 3,
}

impl Kind {
    fn from_byte(b: u8) -> Result<Kind, String> {
        match b {
            1 => Ok(Kind::Passphrase),
            2 => Ok(Kind::Hardware),
            3 => Ok(Kind::Paper),
            _ => Err(format!("unknown share kind {b}")),
        }
    }
    fn on_chain(self) -> bool {
        self != Kind::Paper
    }
}

/// A parsed header. `kinds[i]` is the kind of the share at x = i + 1.
pub struct Header {
    m: u32,
    t: u8,
    salt: [u8; 16],
    pub k: usize,
    pub kinds: Vec<Kind>,
}

impl Header {
    /// The kind of the share at x (1-based), if there is one.
    pub fn kind_at(&self, x: u8) -> Option<Kind> {
        self.kinds.get((x as usize).wrapping_sub(1)).copied()
    }
    /// The x of the passphrase share, if the record has one.
    pub fn passphrase_x(&self) -> Option<u8> {
        self.kinds.iter().position(|&k| k == Kind::Passphrase).map(|i| i as u8 + 1)
    }
    pub fn header_len(&self) -> usize {
        FIXED_HEADER + self.kinds.len()
    }
    /// Masked shares are stored in increasing x, so the layout depends on how many are on chain.
    pub fn record_len(&self) -> usize {
        self.header_len() + 32 * self.kinds.iter().filter(|k| k.on_chain()).count() + NONCE + CT
    }
}

/// The range of Argon2 costs a record may ask for: m in 8..=2^21 KiB (8 is the Argon2 minimum for one
/// lane), t in 1..=16.
fn check_argon_cost(m: u32, t: u8) -> Result<(), String> {
    if !(8..=MAX_M_KIB).contains(&m) || !(1..=MAX_T).contains(&t) {
        return Err(format!("record asks for Argon2 m = {m} KiB, t = {t}; refusing outside m 8..={MAX_M_KIB}, t 1..={MAX_T}"));
    }
    Ok(())
}

/// Parses and validates the header at the start of `bytes` (a record or just a header). Everything in it
/// comes from untrusted input, so nothing here may allocate by an attacker's number.
pub fn parse_header(bytes: &[u8]) -> Result<Header, String> {
    match bytes.first() {
        None => return Err("record is empty".into()),
        Some(&VERSION) => {}
        Some(v) => return Err(format!("unknown record version {v}; only version {VERSION} is supported")),
    }
    let too_short = || "record is too short".to_string();
    let (k, n) = (*bytes.get(22).ok_or_else(too_short)? as usize, *bytes.get(23).ok_or_else(too_short)? as usize);
    if k < 2 || k > n || n > MAX_N {
        return Err(format!("bad k or n: k = {k}, n = {n}; need 2 <= k <= n <= {MAX_N}"));
    }
    let (m, t) = (u32::from_be_bytes(bytes[1..5].try_into().unwrap()), bytes[5]);
    check_argon_cost(m, t)?;
    let kinds = bytes
        .get(FIXED_HEADER..FIXED_HEADER + n)
        .ok_or_else(too_short)?
        .iter()
        .map(|&b| Kind::from_byte(b))
        .collect::<Result<Vec<_>, _>>()?;
    // A second passphrase share would be the same factor under a second pad: no extra security.
    if kinds.iter().filter(|&&k| k == Kind::Passphrase).count() > 1 {
        return Err("at most one passphrase share".into());
    }
    Ok(Header { m, t, salt: bytes[6..22].try_into().unwrap(), k, kinds })
}

/// `parse_header` plus the exact length the header implies. The one check of what makes a record, used
/// by every reader and by `publish` before it spends anything.
pub fn parse_record(record: &[u8]) -> Result<Header, String> {
    let h = parse_header(record)?;
    if record.len() != h.record_len() {
        return Err(format!("not a record for this header (expected {} bytes, got {})", h.record_len(), record.len()));
    }
    Ok(h)
}

/// The header bytes: the AES-GCM associated data and the input to every pad derivation.
pub fn new_header(m: u32, t: u8, salt: &[u8], k: usize, kinds: &[Kind]) -> Result<Vec<u8>, String> {
    assert_eq!(salt.len(), 16, "the salt is 16 bytes");
    let header = [&[VERSION][..], &m.to_be_bytes(), &[t], salt, &[k as u8, kinds.len() as u8], &kinds.iter().map(|&k| k as u8).collect::<Vec<_>>()]
        .concat();
    parse_header(&header)?; // one validator for what we write and what we read
    Ok(header)
}

/// The Argon2id output for the passphrase: v1.3, parallelism 1, 32 bytes, over the NFKD form of the
/// passphrase. The cost is here, so a caller needing the pad of the passphrase share does this once and
/// then calls `pad`.
pub fn stretch_passphrase(passphrase: &str, header: &[u8]) -> Result<[u8; 32], String> {
    let h = parse_header(header)?;
    let params = Params::new(h.m, h.t as u32, 1, Some(32)).map_err(|e| e.to_string())?;
    let normalized: String = passphrase.nfkd().collect();
    let mut argon = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(normalized.as_bytes(), &h.salt, &mut argon)
        .map_err(|e| e.to_string())?;
    Ok(argon)
}

/// The pad for the on-chain share at `x`. `secret` is the Argon2id output (passphrase share) or the
/// 32-byte hardware secret. The label is the share's x, never its position among the masked shares
/// (they differ as soon as a paper share has a smaller x). The label `bk2/<x>` and the whole header are
/// in the HKDF info, so a pad is never reused across shares (a passphrase and a hardware secret that
/// happen to be equal) or records (the hardware secret is the same for every record; the salt in the
/// header is not).
pub fn pad(secret: &[u8], header: &[u8], x: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), secret)
        .expand(&[b"bk2/".as_slice(), &[b'0' + x], header].concat(), &mut out)
        .expect("32 bytes is a valid length");
    out
}

fn cipher(key: &[u8]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key).expect("32-byte key")
}

/// The 33-byte plaintext: entropy length, entropy, then zero padding. The padding is checked on opening,
/// so there is exactly one valid plaintext per seed and nothing can hide in the spare bytes.
fn check_plaintext(plain: &[u8]) -> Result<(), String> {
    let ok = plain.len() == 33
        && ENTROPY_LENGTHS.contains(&(plain[0] as usize))
        && plain[1 + plain[0] as usize..].iter().all(|&b| b == 0);
    if ok { Ok(()) } else { Err("malformed plaintext".into()) }
}

/// `pads` holds (x, pad) for exactly the on-chain shares. `random(n)` is injectable so test vectors can
/// be reproduced; it is called as key(32), then k-1 coefficient vectors (32 each), then nonce(12).
/// Returns the record and the paper shares (x, share). The key is the polynomial's constant term.
pub fn seal(
    header: &[u8],
    pads: &[Share],
    entropy: &[u8],
    random: &mut dyn FnMut(usize) -> Vec<u8>,
) -> Result<(Vec<u8>, Vec<Share>), String> {
    let h = parse_header(header)?;
    if header.len() != h.header_len() {
        return Err("seal takes the header alone".into());
    }
    if !ENTROPY_LENGTHS.contains(&entropy.len()) {
        return Err("entropy must be 16, 20, 24, 28 or 32 bytes".into());
    }
    let mut xs: Vec<u8> = pads.iter().map(|p| p.0).collect();
    xs.sort();
    let on_chain: Vec<u8> = (1..=h.kinds.len() as u8).filter(|&x| h.kinds[x as usize - 1].on_chain()).collect();
    if xs != on_chain {
        return Err(format!("need exactly one pad per on-chain share, at x = {on_chain:?}"));
    }
    let coeffs: Vec<Vec<u8>> = (0..h.k).map(|_| random(32)).collect(); // [key, c1, ..., c_{k-1}]
    let nonce = random(NONCE);
    let mut plain = [0u8; 33];
    plain[0] = entropy.len() as u8;
    plain[1..1 + entropy.len()].copy_from_slice(entropy);
    let ct = cipher(&coeffs[0])
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: header })
        .map_err(|_| "encryption failed".to_string())?;
    let mut record = header.to_vec();
    let mut paper = Vec::new();
    for x in 1..=h.kinds.len() as u8 {
        let y = poly_at(&coeffs, x);
        match pads.iter().find(|p| p.0 == x) {
            Some((_, pad)) => record.extend((0..32).map(|i| y[i] ^ pad[i])),
            None => paper.push((x, y)),
        }
    }
    record.extend(&nonce);
    record.extend(&ct);
    assert_eq!(record.len(), h.record_len());
    Ok((record, paper))
}

/// Opens the record from factors given as (x, 32 bytes): the pad for an on-chain x, the share itself for
/// a paper x. Tries every k-subset, so wrong factors among extras do not matter. Returns the entropy and
/// the x of the factors that opened it. Fewer than k factors is an error, not a guess.
pub fn unseal(record: &[u8], factors: &[Share]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let h = parse_record(record)?;
    let header = &record[..h.header_len()];
    let mut shares: Vec<Share> = Vec::new();
    for &(x, v) in factors {
        let kind = h.kind_at(x).filter(|_| !shares.iter().any(|s| s.0 == x));
        let Some(kind) = kind else { return Err(format!("factor x={x} is out of range or given twice")) };
        let share = if kind.on_chain() {
            // Masked shares are stored in x order; this one is the (number of on-chain shares before x)th.
            let idx = h.kinds[..x as usize - 1].iter().filter(|k| k.on_chain()).count();
            let off = h.header_len() + 32 * idx;
            std::array::from_fn(|i| record[off + i] ^ v[i])
        } else {
            v
        };
        shares.push((x, share));
    }
    if shares.len() < h.k {
        return Err(format!("need at least {} factors, got {}", h.k, shares.len()));
    }
    let nonce_at = h.record_len() - NONCE - CT;
    for mask in 1u32..1 << shares.len() {
        if mask.count_ones() as usize != h.k {
            continue;
        }
        let subset: Vec<Share> = (0..shares.len()).filter(|i| mask >> i & 1 == 1).map(|i| shares[i]).collect();
        let opened = cipher(&interpolate(&subset))
            .decrypt(Nonce::from_slice(&record[nonce_at..nonce_at + NONCE]), Payload { msg: &record[nonce_at + NONCE..], aad: header });
        if let Ok(plain) = opened {
            check_plaintext(&plain)?;
            return Ok((plain[1..1 + plain[0] as usize].to_vec(), subset.iter().map(|s| s.0).collect()));
        }
    }
    Err(format!("decryption failed: at least {} of the factors given must be correct, or the record is corrupted", h.k))
}

/// All the cheap checks of `restore`, so that nothing slow (a hardware key's PIN and touch, Argon2)
/// starts until the factors are known to be usable: the record parses, every factor is at an x of its
/// own kind and appears once, paper words decode, and there are at least k factors. `hardware` is just
/// the x of each hardware share to be used. Returns the decoded paper shares.
/// Errors never contain the words given: a mistyped word is probably a secret.
pub fn check_factors(
    record: &[u8],
    passphrase: bool,
    hardware: &[u8],
    paper: &[(u8, &str)],
) -> Result<Vec<Share>, String> {
    let h = parse_record(record)?;
    let mut seen: Vec<u8> = Vec::new();
    if passphrase {
        seen.push(h.passphrase_x().ok_or("this record has no passphrase share")?);
    }
    let mut note = |x: u8, want: Kind, what: &str| -> Result<(), String> {
        if h.kind_at(x) != Some(want) {
            return Err(format!("share {x} is not a {what} share of this record"));
        }
        if seen.contains(&x) {
            return Err(format!("share {x} is given twice"));
        }
        seen.push(x);
        Ok(())
    };
    for &x in hardware {
        note(x, Kind::Hardware, "hardware")?;
    }
    let mut shares = Vec::new();
    for &(x, words) in paper {
        note(x, Kind::Paper, "paper")?;
        let share = share_from_words(words).map_err(|_| format!("paper share {x} is not 24 valid BIP39 words with a correct checksum"))?;
        shares.push((x, share));
    }
    if seen.len() < h.k {
        return Err(format!("need at least {} factors, got {}", h.k, seen.len()));
    }
    Ok(shares)
}

/// Restore from what a person holds: the passphrase, hardware secrets as (x, 32 bytes) and paper shares
/// as (x, 24 words). The x of a hardware or paper share is printed with it at backup time; a factor at
/// an x of the wrong kind is refused rather than tried. Returns the seed words and the x that opened it.
pub fn restore(
    record: &[u8],
    passphrase: Option<&str>,
    hardware: &[Share],
    paper: &[(u8, &str)],
) -> Result<(String, Vec<u8>), String> {
    // Everything cheap first: the Argon2 below costs seconds and its parameters come from the header.
    let xs: Vec<u8> = hardware.iter().map(|h| h.0).collect();
    let mut factors = check_factors(record, passphrase.is_some(), &xs, paper)?;
    let h = parse_header(record)?;
    let header = &record[..h.header_len()];
    for &(x, secret) in hardware {
        factors.push((x, pad(&secret, header, x)));
    }
    if let Some(p) = passphrase {
        let x = h.passphrase_x().expect("check_factors saw a passphrase share");
        factors.push((x, pad(&stretch_passphrase(p, header)?, header, x)));
    }
    let (entropy, used) = unseal(record, &factors)?;
    Ok((entropy_to_words(&entropy), used))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon_cost_bounds() {
        assert!(check_argon_cost(8, 1).is_ok());
        assert!(check_argon_cost(1 << 21, 16).is_ok(), "the caps themselves are allowed");
        for (m, t) in [(7, 1), (1024, 0), ((1 << 21) + 1, 1), (1024, 17), (u32::MAX, 255)] {
            assert!(check_argon_cost(m, t).is_err(), "m={m} t={t}");
        }
        assert!(check_argon_cost((1 << 21) + 1, 1).unwrap_err().contains("refusing"));
        assert!(check_argon_cost(1024, 17).unwrap_err().contains("refusing"));
        // A header is refused before any work, whoever made it; t = 16 at the smallest memory is fast.
        let kinds = [Kind::Passphrase, Kind::Hardware];
        assert!(new_header(1024, 17, &[0; 16], 2, &kinds).is_err());
        assert!(new_header(1 << 22, 1, &[0; 16], 2, &kinds).is_err());
        assert!(stretch_passphrase("x", &new_header(8, 16, &[0; 16], 2, &kinds).unwrap()).is_ok());
    }
}
