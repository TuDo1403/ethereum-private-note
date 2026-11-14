//! Record format v2 (see "Format v2" in ../../SPEC.md): general k-of-n Shamir, 2 <= k <= n <= 5.
//! Every share has a kind. Passphrase and hardware shares are stored on chain, masked with a pad; paper
//! shares are never in the record. `tests/vectors_v2.rs` rebuilds ../../vectors-v2.json byte for byte.
//! v1 (lib.rs) is untouched and keeps working.

use super::{argon2id, entropy_to_words, ginv, gmul, hkdf_pad, words_to_entropy};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

pub const VERSION: u8 = 2;
pub const MAX_N: usize = 5;
/// version, m, t, salt, k, n; the kinds follow, one byte per share.
const FIXED_HEADER: usize = 24;
/// nonce, then 33 bytes of padded plaintext and the 16-byte GCM tag.
const NONCE: usize = 12;
const CT: usize = 33 + 16;

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
    pub m: u32,
    pub t: u8,
    pub salt: [u8; 16],
    pub k: usize,
    pub kinds: Vec<Kind>,
}

impl Header {
    pub fn len(&self) -> usize {
        FIXED_HEADER + self.kinds.len()
    }
    /// Masked shares are stored in increasing x, so the layout depends on how many are on chain.
    pub fn record_len(&self) -> usize {
        self.len() + 32 * self.kinds.iter().filter(|k| k.on_chain()).count() + NONCE + CT
    }
}

/// Parses and validates the header at the start of `bytes` (a record or just a header). Everything in it
/// comes from untrusted input, so nothing here may allocate by an attacker's number.
pub fn parse_header(bytes: &[u8]) -> Result<Header, String> {
    if bytes.len() < FIXED_HEADER || bytes[0] != VERSION {
        return Err("not a v2 record".into());
    }
    let (k, n) = (bytes[22] as usize, bytes[23] as usize);
    if k < 2 || k > n || n > MAX_N || bytes.len() < FIXED_HEADER + n {
        return Err("not a v2 record (bad k or n)".into());
    }
    let (m, t) = (u32::from_be_bytes(bytes[1..5].try_into().unwrap()), bytes[5]);
    super::check_argon_cost(m, t)?;
    let kinds = bytes[FIXED_HEADER..FIXED_HEADER + n].iter().map(|&b| Kind::from_byte(b)).collect::<Result<Vec<_>, _>>()?;
    // A second passphrase share would be the same factor under a second pad: no extra security.
    if kinds.iter().filter(|&&k| k == Kind::Passphrase).count() > 1 {
        return Err("at most one passphrase share".into());
    }
    Ok(Header {
        m,
        t,
        salt: bytes[6..22].try_into().unwrap(),
        k,
        kinds,
    })
}

/// The header bytes: the AES-GCM associated data and the input to every pad derivation.
pub fn new_header(m: u32, t: u8, salt: &[u8], k: usize, kinds: &[Kind]) -> Result<Vec<u8>, String> {
    assert_eq!(salt.len(), 16, "the salt is 16 bytes");
    let header = [&[VERSION][..], &m.to_be_bytes(), &[t], salt, &[k as u8, kinds.len() as u8], &kinds.iter().map(|&k| k as u8).collect::<Vec<_>>()]
        .concat();
    parse_header(&header)?; // one validator for what we write and what we read
    Ok(header)
}

/// 2-of-3: passphrase (x=1), YubiKey (x=2), paper (x=3).
pub fn header_2_of_3(m: u32, t: u8, salt: &[u8]) -> Vec<u8> {
    new_header(m, t, salt, 2, &[Kind::Passphrase, Kind::Hardware, Kind::Paper]).expect("valid preset")
}

/// 3-of-5: passphrase (x=1), two YubiKeys (x=2,3), two paper (x=4,5).
pub fn header_3_of_5(m: u32, t: u8, salt: &[u8]) -> Vec<u8> {
    new_header(m, t, salt, 3, &[Kind::Passphrase, Kind::Hardware, Kind::Hardware, Kind::Paper, Kind::Paper]).expect("valid preset")
}

/// The Argon2id output for the passphrase. The cost is here, so a caller needing the pad of the
/// passphrase share does this once and then calls `pad`.
pub fn stretch_passphrase(passphrase: &str, header: &[u8]) -> Result<[u8; 32], String> {
    let h = parse_header(header)?;
    argon2id(passphrase, h.m, h.t, &h.salt)
}

/// The pad for the on-chain share at `x`. `secret` is the Argon2id output (passphrase share) or the
/// 32-byte hardware secret. The label `bk2/<x>` and the whole header are in the HKDF info, so a pad is
/// never reused across shares (a passphrase and a hardware secret that happen to be equal) or records
/// (the hardware secret is the same for every record; the salt in the header is not).
pub fn pad(secret: &[u8], header: &[u8], x: u8) -> [u8; 32] {
    hkdf_pad(secret, &[b"bk2/".as_slice(), &[b'0' + x], header].concat())
}

/// Value of the share polynomial at x, byte by byte: coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 ... (Horner).
fn poly_at(coeffs: &[Vec<u8>], x: u8) -> [u8; 32] {
    std::array::from_fn(|i| coeffs.iter().rev().fold(0, |acc, c| gmul(acc, x) ^ c[i]))
}

/// The polynomial at 0 from k points with distinct nonzero x. In characteristic 2 "minus" is xor, so
/// the Lagrange weight of point i is the product over j != i of x_j / (x_i ^ x_j).
fn interpolate(points: &[(u8, [u8; 32])]) -> [u8; 32] {
    let mut secret = [0u8; 32];
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let weight = points
            .iter()
            .enumerate()
            .filter(|&(j, _)| j != i)
            .fold(1, |w, (_, &(xj, _))| gmul(w, gmul(xj, ginv(xi ^ xj))));
        for b in 0..32 {
            secret[b] ^= gmul(yi[b], weight);
        }
    }
    secret
}

/// `pads` holds (x, pad) for exactly the on-chain shares. `random(n)` is injectable so test vectors can
/// be reproduced; it is called as key(32), then k-1 coefficient vectors (32 each), then nonce(12).
/// Returns the record and the paper shares (x, share). The key is the polynomial's constant term.
pub fn seal(
    header: &[u8],
    pads: &[(u8, [u8; 32])],
    entropy: &[u8],
    random: &mut dyn FnMut(usize) -> Vec<u8>,
) -> Result<(Vec<u8>, Vec<(u8, [u8; 32])>), String> {
    let h = parse_header(header)?;
    if header.len() != h.len() {
        return Err("seal takes the header alone".into());
    }
    if ![16, 20, 24, 28, 32].contains(&entropy.len()) {
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
    let ct = Aes256Gcm::new_from_slice(&coeffs[0])
        .expect("32-byte key")
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: header })
        .map_err(|_| "encryption failed".to_string())?;
    let mut record = header.to_vec();
    let mut paper = Vec::new();
    for &x in &(1..=h.kinds.len() as u8).collect::<Vec<_>>() {
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
pub fn unseal(record: &[u8], factors: &[(u8, [u8; 32])]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let h = parse_header(record)?;
    if record.len() != h.record_len() {
        return Err(format!("not a v2 record for this header (expected {} bytes)", h.record_len()));
    }
    let header = &record[..h.len()];
    let mut shares: Vec<(u8, [u8; 32])> = Vec::new();
    for &(x, v) in factors {
        if x == 0 || x as usize > h.kinds.len() || shares.iter().any(|s| s.0 == x) {
            return Err(format!("factor x={x} is out of range or given twice"));
        }
        let share = if h.kinds[x as usize - 1].on_chain() {
            // Masked shares are stored in x order; this one is the (number of on-chain shares before x)th.
            let idx = h.kinds[..x as usize - 1].iter().filter(|k| k.on_chain()).count();
            let off = h.len() + 32 * idx;
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
        let subset: Vec<(u8, [u8; 32])> = (0..shares.len()).filter(|i| mask >> i & 1 == 1).map(|i| shares[i]).collect();
        let opened = Aes256Gcm::new_from_slice(&interpolate(&subset))
            .expect("32-byte key")
            .decrypt(Nonce::from_slice(&record[nonce_at..nonce_at + NONCE]), Payload { msg: &record[nonce_at + NONCE..], aad: header });
        if let Ok(plain) = opened {
            if plain.len() != 33 || ![16, 20, 24, 28, 32].contains(&(plain[0] as usize)) {
                return Err("malformed plaintext".into());
            }
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
) -> Result<Vec<(u8, [u8; 32])>, String> {
    let h = parse_header(record)?;
    if record.len() != h.record_len() {
        return Err(format!("not a v2 record for this header (expected {} bytes)", h.record_len()));
    }
    let kind_at = |x: u8| h.kinds.get((x as usize).wrapping_sub(1)).copied();
    let mut seen: Vec<u8> = Vec::new();
    if passphrase {
        let x = h.kinds.iter().position(|&k| k == Kind::Passphrase).ok_or("this record has no passphrase share")?;
        seen.push(x as u8 + 1);
    }
    let mut note = |x: u8, want: Kind, what: &str| -> Result<(), String> {
        if kind_at(x) != Some(want) {
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
        let share = words_to_entropy(words).ok().and_then(|e| <[u8; 32]>::try_from(e).ok());
        shares.push((x, share.ok_or(format!("paper share {x} is not 24 valid BIP39 words with a correct checksum"))?));
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
    hardware: &[(u8, [u8; 32])],
    paper: &[(u8, &str)],
) -> Result<(String, Vec<u8>), String> {
    // Everything cheap first: the Argon2 below costs seconds and its parameters come from the header.
    let xs: Vec<u8> = hardware.iter().map(|h| h.0).collect();
    let mut factors = check_factors(record, passphrase.is_some(), &xs, paper)?;
    let h = parse_header(record)?;
    let header = &record[..h.len()];
    for &(x, secret) in hardware {
        factors.push((x, pad(&secret, header, x)));
    }
    if let Some(p) = passphrase {
        let x = h.kinds.iter().position(|&k| k == Kind::Passphrase).unwrap() as u8 + 1;
        factors.push((x, pad(&stretch_passphrase(p, header)?, header, x)));
    }
    let (entropy, used) = unseal(record, &factors)?;
    Ok((entropy_to_words(&entropy), used))
}
