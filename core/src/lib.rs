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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// First 4 bytes of SHA-256 over the seed entropy, as hex. Lets a person check that a test restore gave
/// the seed they backed up without showing the seed. 32 bits of a hash leave a 128-bit seed with 96 bits
/// an attacker must still search, so writing it on the public sheet costs nothing that matters.
pub fn seed_fingerprint(entropy: &[u8]) -> String {
    hex(&Sha256::digest(entropy)[..4])
}

/// First 8 bytes of SHA-256 over the record bytes, as hex: a short name for one record, printed by
/// `vault` on the recovery sheet and by `publish` after storing it.
pub fn record_id(record: &[u8]) -> String {
    hex(&Sha256::digest(record)[..8])
}

// GF(2^8) with the AES polynomial; 0x11b without its top bit is 0x1b. `a` is often a secret byte, so
// there are no data-dependent branches or loop counts: masks (0x00 or 0xff) replace the `if`s.
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    for _ in 0..8 {
        p ^= a & (b & 1).wrapping_neg();
        a = (a << 1) ^ (0x1b & (a >> 7).wrapping_neg());
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
    for (n, w) in words.iter().enumerate() {
        // Position only, never the text: a mistyped seed or share word is still mostly a secret.
        let i = list.iter().position(|x| x == w).ok_or(format!("word {} is not a BIP39 word", n + 1))?;
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

/// The 33-byte plaintext of both formats: entropy length, entropy, then zero padding. The padding is
/// checked too, so there is exactly one valid plaintext per seed and nothing can hide in the spare bytes.
pub(crate) fn check_plaintext(plain: &[u8]) -> Result<(), String> {
    let ok = plain.len() == 33
        && [16, 20, 24, 28, 32].contains(&(plain[0] as usize))
        && plain[1 + plain[0] as usize..].iter().all(|&b| b == 0);
    if ok { Ok(()) } else { Err("malformed plaintext".into()) }
}

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
                check_plaintext(&plain)?;
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

/// All the cheap checks of a v1 `restore`, so nothing slow (the YubiKey's PIN and touch, Argon2) starts
/// until the factors are known to be usable: the record is v1, share C (if given) decodes, at least two
/// factors are given, and the Argon2 cost is in range when the passphrase will be stretched. Returns
/// share C decoded. Errors never contain the words given.
pub fn check_factors(record: &[u8], passphrase: bool, passkey: bool, share_c: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    if record.len() != RECORD || record[0] != 1 {
        return Err(format!("not a v1 record (expected {RECORD} bytes)"));
    }
    let c = share_c.map(|w| share_c_from_words(w).map_err(|e| format!("share C: {e}"))).transpose()?;
    if [passphrase, passkey, c.is_some()].iter().filter(|&&b| b).count() < 2 {
        return Err("need two of: passphrase, passkey, share C".into());
    }
    if passphrase {
        check_argon_cost(u32::from_be_bytes(record[1..5].try_into().unwrap()), record[5])?;
    }
    Ok(c)
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
    let c = check_factors(record, passphrase.is_some(), prf.is_some(), share_c)?;
    let header = &record[..HEADER];
    let f = Factors {
        a: passphrase.map(|p| derive_pad_a(p, header).map(|(_, pad)| pad)).transpose()?,
        b: prf.map(|p| derive_pad_b(p, header)).transpose()?,
        c,
    };
    let (entropy, used) = unseal(record, &f)?;
    Ok((entropy_to_words(&entropy), used))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_free_gmul_matches_the_textbook_one() {
        fn reference(mut a: u8, mut b: u8) -> u8 {
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
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(gmul(a, b), reference(a, b), "{a} * {b}");
            }
        }
    }

    #[test]
    fn word_errors_name_the_position_never_the_text() {
        let typo = "legal winner thank year hunter2 sausage worth useful legal winner thank yellow";
        let e = words_to_entropy(typo).unwrap_err();
        assert_eq!(e, "word 5 is not a BIP39 word");
        let e = share_c_from_words(&format!("{} hunter2", ["abandon"; 23].join(" "))).unwrap_err();
        assert!(e.contains("word 24") && !e.contains("hunter2"), "{e}");
    }

    #[test]
    fn fingerprint_and_record_id() {
        // A checksum-valid typo ("wave" -> "wage") gives another seed; the fingerprint shows it.
        let seed = words_to_entropy("legal winner thank year wave sausage worth useful legal winner thank yellow").unwrap();
        let typo = words_to_entropy("legal winner thank year wage sausage worth useful legal winner thank yellow").unwrap();
        assert_eq!(seed_fingerprint(&seed), "87dcde7f");
        assert_eq!(seed_fingerprint(&typo), "8b4cedd3");
        assert_eq!(record_id(b""), "e3b0c44298fc1c14"); // SHA-256("") starts e3b0c442 98fc1c14
    }

    #[test]
    fn nonzero_plaintext_padding_is_refused() {
        let header = new_header(1024, 1, &[0; 16]);
        let (pa, pb) = ([1u8; 32], [2u8; 32]);
        let rnd: Vec<u8> = (0..76u8).collect(); // key(32) line(32) nonce(12)
        let mut off = 0;
        let mut take = |n: usize| {
            off += n;
            rnd[off - n..off].to_vec()
        };
        let (mut record, c) = seal(&header, &pa, &pb, &[7; 16], &mut take).unwrap();
        let f = Factors { a: Some(pa), b: None, c: Some(c) };
        assert_eq!(unseal(&record, &f).unwrap().0, vec![7; 16]);
        // Same key and nonce, one padding byte set: authenticates, but must still be refused.
        let mut plain = [0u8; 33];
        plain[0] = 16;
        plain[1..17].fill(7);
        plain[32] = 1;
        let ct = Aes256Gcm::new_from_slice(&rnd[..32])
            .unwrap()
            .encrypt(Nonce::from_slice(&record[86..98]), Payload { msg: &plain, aad: &header })
            .unwrap();
        record[98..].copy_from_slice(&ct);
        assert_eq!(unseal(&record, &f).unwrap_err(), "malformed plaintext");
    }

    #[test]
    fn cheap_checks_come_before_argon2() {
        // m above the cap: had Argon2 run first, the error would be "refusing ...".
        let mut record = vec![0u8; RECORD];
        record[..HEADER].copy_from_slice(&new_header(u32::MAX, 3, &[0; 16]));
        let bad_c = format!("{} zebra", ["abandon"; 23].join(" ")); // valid words, wrong checksum
        let e = restore(&record, Some("pass"), None, Some(&bad_c)).unwrap_err();
        assert!(e.starts_with("share C:"), "{e}");
        assert!(restore(&record, Some("pass"), None, None).unwrap_err().contains("need two"));
        assert!(check_factors(&record, true, true, None).unwrap_err().contains("refusing"));
        // Without the passphrase the Argon2 cost does not matter.
        let good_c = format!("{} art", ["abandon"; 23].join(" "));
        assert_eq!(check_factors(&record, false, true, Some(&good_c)).unwrap(), Some([0; 32]));
    }
}
