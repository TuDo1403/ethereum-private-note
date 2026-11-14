//! The reference implementation of ../SPEC.md: backup (`seal`) and restore from any two of passphrase,
//! passkey secret (see `fido`) and share C. `tests/vectors.rs` rebuilds every record in ../vectors.json
//! byte for byte, which is the evidence the format is portable: an implementation in another language
//! is correct if it reproduces the same vectors.

pub mod fido;
pub mod v2;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

const WORDS: &str = include_str!("../wordlist.txt");
const HEADER: usize = 22;
pub const RECORD: usize = 147;
// m comes from the record, i.e. from untrusted input. Refuse absurd values (2 GiB, twice the real
// 1 GiB) instead of trying to allocate them.
const MAX_M_KIB: u32 = 1 << 21;
// t comes from the record too, and each pass costs as much time as the whole 1 GiB hash; the real
// parameter is 3. 16 leaves room to raise it later and still bounds the time a forged record can burn.
pub const MAX_T: u8 = 16;

/// The range of Argon2 costs a record may ask for: m in 8..=2^21 KiB (8 is the Argon2 minimum for one
/// lane), t in 1..=16. Checked on untrusted headers before any work is done.
pub fn check_argon_cost(m: u32, t: u8) -> Result<(), String> {
    if m > MAX_M_KIB {
        return Err(format!("record asks for {m} KiB of Argon2 memory; refusing above {MAX_M_KIB}"));
    }
    if t > MAX_T {
        return Err(format!("record asks for {t} Argon2 passes; refusing above {MAX_T}"));
    }
    if m < 8 || t < 1 {
        return Err("record asks for Argon2 memory below 8 KiB or no passes".into());
    }
    Ok(())
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 || !s.is_ascii() {
        return Err("not a hex string".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| "not a hex string".to_string()))
        .collect()
}

// GF(2^8) with the AES polynomial; 0x11b without its top bit is 0x1b.
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
        b >>= 1;
    }
    p
}

fn ginv(a: u8) -> u8 {
    (0..254).fold(1, |r, _| gmul(r, a)) // a^254
}

fn hkdf_pad(secret: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), secret).expand(info, &mut out).expect("32 bytes is a valid length");
    out
}

pub fn words_to_entropy(words: &str) -> Result<Vec<u8>, String> {
    let list: Vec<&str> = WORDS.split_whitespace().collect();
    let words: Vec<String> = words.split_whitespace().map(str::to_lowercase).collect();
    if ![12, 15, 18, 21, 24].contains(&words.len()) {
        return Err("mnemonic must be 12, 15, 18, 21 or 24 words".into());
    }
    let mut bits = Vec::new();
    for w in &words {
        let i = list.iter().position(|x| x == w).ok_or(format!("not a BIP39 word: \"{w}\""))?;
        bits.extend((0..11).rev().map(|k| (i >> k) & 1 == 1));
    }
    let entropy_bits = bits.len() - words.len() / 3;
    let entropy: Vec<u8> =
        bits[..entropy_bits].chunks(8).map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | b as u8)).collect();
    let digest = Sha256::digest(&entropy);
    for (k, &bit) in bits[entropy_bits..].iter().enumerate() {
        if bit != ((digest[0] >> (7 - k)) & 1 == 1) {
            return Err("mnemonic checksum is wrong (typo or wrong word order)".into());
        }
    }
    Ok(entropy)
}

pub fn entropy_to_words(entropy: &[u8]) -> String {
    let list: Vec<&str> = WORDS.split_whitespace().collect();
    let digest = Sha256::digest(entropy);
    let mut bits: Vec<bool> = entropy.iter().flat_map(|b| (0..8).rev().map(move |k| (b >> k) & 1 == 1)).collect();
    bits.extend((0..entropy.len() / 4).map(|k| (digest[0] >> (7 - k)) & 1 == 1));
    bits.chunks(11).map(|c| list[c.iter().fold(0usize, |a, &b| (a << 1) | b as usize)]).collect::<Vec<_>>().join(" ")
}

/// Returns the raw Argon2id output and padA. The raw output is exposed only so tests can pinpoint
/// which step disagrees with vectors.json.
pub fn derive_pad_a(passphrase: &str, header: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let m = u32::from_be_bytes(header[1..5].try_into().unwrap());
    let argon = argon2id(passphrase, m, header[5], &header[6..22])?;
    Ok((argon, hkdf_pad(&argon, &[b"bk1/A".as_slice(), header].concat())))
}

/// Argon2id v1.3, parallelism 1, 32-byte output, over the NFKD form of the passphrase. Shared by v1 and
/// v2; `m` comes from an untrusted record, hence the cap.
pub(crate) fn argon2id(passphrase: &str, m: u32, t: u8, salt: &[u8]) -> Result<[u8; 32], String> {
    check_argon_cost(m, t)?;
    let params = Params::new(m, t as u32, 1, Some(32)).map_err(|e| e.to_string())?;
    let normalized: String = passphrase.nfkd().collect();
    let mut argon = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(normalized.as_bytes(), salt, &mut argon)
        .map_err(|e| e.to_string())?;
    Ok(argon)
}

/// Pad B from the 32-byte secret of the second factor (the YubiKey's hmac-secret output).
pub fn derive_pad_b(prf: &[u8], header: &[u8]) -> Result<[u8; 32], String> {
    if prf.len() != 32 {
        return Err("passkey secret must be 32 bytes".into());
    }
    Ok(hkdf_pad(prf, &[b"bk1/B".as_slice(), header].concat()))
}

/// 1 GiB, 3 passes. A restore needs this much free memory, so do not pick a number your recovery
/// machine cannot allocate.
pub const ARGON_M_KIB: u32 = 1 << 20;
pub const ARGON_T: u8 = 3;

pub fn new_header(m: u32, t: u8, salt: &[u8]) -> Vec<u8> {
    assert_eq!(salt.len(), 16, "the salt is 16 bytes");
    [&[1u8][..], &m.to_be_bytes(), &[t], salt].concat()
}

/// OS randomness. Failing loudly is the only safe answer: a backup made with bad randomness is worse than none.
pub fn os_random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("the OS random source failed; refusing to continue");
    b
}

/// The passphrase is the only low-entropy factor, and anyone holding one other factor can test guesses
/// against the public record offline, forever. So it is generated, never chosen by a person.
/// 2048 = 2^11 divides 2^16, so masking 16 random bits down to 11 is unbiased; 7 words = 77 bits.
pub fn new_passphrase(words: usize, random: &mut dyn FnMut(usize) -> Vec<u8>) -> String {
    let list: Vec<&str> = WORDS.split_whitespace().collect();
    let r = random(2 * words);
    (0..words).map(|i| list[(((r[2 * i] as usize) << 8) | r[2 * i + 1] as usize) & 2047]).collect::<Vec<_>>().join(" ")
}

/// `random(n)` is injectable only so test vectors can be reproduced; it is called as key(32), line(32), nonce(12).
/// Returns the 147-byte record and share C (the share at x=3, never stored on chain).
pub fn seal(
    header: &[u8],
    pad_a: &[u8; 32],
    pad_b: &[u8; 32],
    entropy: &[u8],
    random: &mut dyn FnMut(usize) -> Vec<u8>,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    if ![16, 20, 24, 28, 32].contains(&entropy.len()) {
        return Err("entropy must be 16, 20, 24, 28 or 32 bytes".into());
    }
    let key = random(32);
    let line = random(32);
    let mut plain = [0u8; 33];
    plain[0] = entropy.len() as u8;
    plain[1..1 + entropy.len()].copy_from_slice(entropy);
    let nonce = random(12);
    let ct = Aes256Gcm::new_from_slice(&key)
        .expect("32-byte key")
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: header })
        .map_err(|_| "encryption failed".to_string())?;
    // Share at x is key XOR line*x; A and B are additionally masked with their pads.
    let share = |x: u8| -> Vec<u8> { (0..32).map(|i| key[i] ^ gmul(line[i], x)).collect() };
    let masked = |x: u8, pad: &[u8; 32]| -> Vec<u8> { share(x).iter().zip(pad).map(|(s, p)| s ^ p).collect() };
    let record = [header, &masked(1, pad_a), &masked(2, pad_b), &nonce, &ct].concat();
    assert_eq!(record.len(), RECORD);
    Ok((record, share(3).try_into().expect("32 bytes")))
}

/// What the caller holds: pads for A and B (the record stores those shares masked), and share C itself.
#[derive(Default)]
pub struct Factors {
    pub a: Option<[u8; 32]>,
    pub b: Option<[u8; 32]>,
    pub c: Option<[u8; 32]>,
}

const NAMES: [&str; 3] = ["A", "B", "C"];

/// Tries every pair of the factors given, so one wrong factor does not matter as long as the other two
/// are right. Returns the entropy and which pair worked.
pub fn unseal(record: &[u8], f: &Factors) -> Result<(Vec<u8>, String), String> {
    if record.len() != RECORD || record[0] != 1 {
        return Err(format!("not a v1 record (expected {RECORD} bytes)"));
    }
    let header = &record[..HEADER];
    let unmask = |enc: &[u8], pad: &[u8; 32]| -> [u8; 32] {
        std::array::from_fn(|i| enc[i] ^ pad[i])
    };
    let mut shares: Vec<(u8, [u8; 32])> = Vec::new();
    if let Some(p) = &f.a {
        shares.push((1, unmask(&record[22..54], p)));
    }
    if let Some(p) = &f.b {
        shares.push((2, unmask(&record[54..86], p)));
    }
    if let Some(y) = f.c {
        shares.push((3, y));
    }
    if shares.len() < 2 {
        return Err("need two of: passphrase, passkey, share C".into());
    }
    for i in 0..shares.len() {
        for j in i + 1..shares.len() {
            let ((x1, y1), (x2, y2)) = (shares[i], shares[j]);
            // line = (y1^y2) / (x1^x2), key = y1 ^ line*x1.
            let inv = ginv(x1 ^ x2);
            let key: Vec<u8> = (0..32).map(|k| y1[k] ^ gmul(gmul(y1[k] ^ y2[k], inv), x1)).collect();
            let opened = Aes256Gcm::new_from_slice(&key)
                .expect("32-byte key")
                .decrypt(Nonce::from_slice(&record[86..98]), Payload { msg: &record[98..], aad: header });
            if let Ok(plain) = opened {
                if plain.len() != 33 || ![16, 20, 24, 28, 32].contains(&(plain[0] as usize)) {
                    return Err("malformed plaintext".into());
                }
                let used = format!("{}+{}", NAMES[x1 as usize - 1], NAMES[x2 as usize - 1]);
                return Ok((plain[1..1 + plain[0] as usize].to_vec(), used));
            }
        }
    }
    Err("decryption failed: at least two of the factors given must be correct, or the record is corrupted".into())
}

/// The BIP39 word meant by what was typed: an exact word, or a prefix (3+ letters) of exactly one word.
/// An exact match wins, so "add" is the word `add` even though `addict` and `address` start with it.
pub fn complete_word(typed: &str) -> Option<&'static str> {
    let t = typed.trim().to_lowercase();
    if t.len() < 3 {
        return None;
    }
    if let Some(w) = WORDS.split_whitespace().find(|w| *w == t) {
        return Some(w);
    }
    let mut hits = WORDS.split_whitespace().filter(|w| w.starts_with(&t));
    match (hits.next(), hits.next()) {
        (Some(w), None) => Some(w),
        _ => None,
    }
}

pub fn share_c_from_words(words: &str) -> Result<[u8; 32], String> {
    words_to_entropy(words)?.try_into().map_err(|_| "share C must be 24 words".to_string())
}

/// Restore from any two of: passphrase, the passkey's 32-byte secret, share C words. Returns the seed
/// words and which pair opened the record.
pub fn restore(
    record: &[u8],
    passphrase: Option<&str>,
    prf: Option<&[u8]>,
    share_c: Option<&str>,
) -> Result<(String, String), String> {
    // Checked first: derive_pad_a reads the header and costs seconds of Argon2.
    if record.len() != RECORD || record[0] != 1 {
        return Err(format!("not a v1 record (expected {RECORD} bytes)"));
    }
    let header = &record[..HEADER];
    let f = Factors {
        a: passphrase.map(|p| derive_pad_a(p, header).map(|(_, pad)| pad)).transpose()?,
        b: prf.map(|p| derive_pad_b(p, header)).transpose()?,
        c: share_c.map(share_c_from_words).transpose()?,
    };
    let (entropy, used) = unseal(record, &f)?;
    Ok((entropy_to_words(&entropy), used))
}
