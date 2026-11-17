//! BIP39 English words: seed words, the 24-word paper share and the generated passphrase.

use sha2::{Digest, Sha256};
use std::sync::LazyLock;

static WORDS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| include_str!("../wordlist.txt").split_whitespace().collect());

pub fn words_to_entropy(words: &str) -> Result<Vec<u8>, String> {
    let words: Vec<String> = words.split_whitespace().map(str::to_lowercase).collect();
    if ![12, 15, 18, 21, 24].contains(&words.len()) {
        return Err("mnemonic must be 12, 15, 18, 21 or 24 words".into());
    }
    let mut bits = Vec::new();
    for (n, w) in words.iter().enumerate() {
        // Position only, never the text: a mistyped seed or share word is still mostly a secret.
        let i = WORDS
            .iter()
            .position(|x| x == w)
            .ok_or(format!("word {} is not a BIP39 word", n + 1))?;
        bits.extend((0..11).rev().map(|k| (i >> k) & 1 == 1));
    }
    let entropy_bits = bits.len() - words.len() / 3;
    let entropy: Vec<u8> = bits[..entropy_bits]
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | b as u8))
        .collect();
    let digest = Sha256::digest(&entropy);
    for (k, &bit) in bits[entropy_bits..].iter().enumerate() {
        if bit != ((digest[0] >> (7 - k)) & 1 == 1) {
            return Err("mnemonic checksum is wrong (typo or wrong word order)".into());
        }
    }
    Ok(entropy)
}

pub fn entropy_to_words(entropy: &[u8]) -> String {
    let digest = Sha256::digest(entropy);
    let mut bits: Vec<bool> = entropy
        .iter()
        .flat_map(|b| (0..8).rev().map(move |k| (b >> k) & 1 == 1))
        .collect();
    bits.extend((0..entropy.len() / 4).map(|k| (digest[0] >> (7 - k)) & 1 == 1));
    bits.chunks(11)
        .map(|c| WORDS[c.iter().fold(0usize, |a, &b| (a << 1) | b as usize)])
        .collect::<Vec<_>>()
        .join(" ")
}

/// A paper share is 32 bytes written as 24 words.
pub fn share_from_words(words: &str) -> Result<[u8; 32], String> {
    words_to_entropy(words)?
        .try_into()
        .map_err(|_| "a paper share must be 24 words".to_string())
}

/// The passphrase is the only low-entropy factor, and anyone holding enough other factors can test guesses
/// against the public record offline, forever. So it is generated, never chosen by a person.
/// 2048 = 2^11 divides 2^16, so masking 16 random bits down to 11 is unbiased; 12 words = 132 bits.
pub fn new_passphrase(words: usize) -> String {
    let r = crate::os_random(2 * words);
    (0..words)
        .map(|i| WORDS[(((r[2 * i] as usize) << 8) | r[2 * i + 1] as usize) & 2047])
        .collect::<Vec<_>>()
        .join(" ")
}

/// The BIP39 word meant by what was typed: an exact word, or a prefix (3+ letters) of exactly one word.
/// An exact match wins, so "add" is the word `add` even though `addict` and `address` start with it.
pub fn complete_word(typed: &str) -> Option<&'static str> {
    let t = typed.trim().to_lowercase();
    if t.len() < 3 {
        return None;
    }
    if let Some(w) = WORDS.iter().find(|w| **w == t) {
        return Some(w);
    }
    let mut hits = WORDS.iter().filter(|w| w.starts_with(&t));
    match (hits.next(), hits.next()) {
        (Some(w), None) => Some(w),
        _ => None,
    }
}

/// Every BIP39 word that starts with `prefix` (already lowercase), in list order. A word picker uses it to
/// refuse a key that no word can follow and to show what is left to choose from.
pub fn words_with_prefix(prefix: &str) -> Vec<&'static str> {
    WORDS
        .iter()
        .copied()
        .filter(|w| w.starts_with(prefix))
        .collect()
}

/// The passphrase is generated with this many words (132 bits); restore asks for exactly as many.
pub const PASSPHRASE_WORDS: usize = 12;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_has_2048_words_and_round_trips() {
        assert_eq!(WORDS.len(), 2048);
        // The canonical BIP39 English list, byte for byte: one wrong word would corrupt seeds silently.
        assert_eq!(
            crate::hex(Sha256::digest(include_str!("../wordlist.txt"))),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        let seed = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        assert_eq!(entropy_to_words(&words_to_entropy(seed).unwrap()), seed);
        assert_eq!(new_passphrase(12).split(' ').count(), 12);
    }

    #[test]
    fn word_errors_name_the_position_never_the_text() {
        let typo = "legal winner thank year hunter2 sausage worth useful legal winner thank yellow";
        assert_eq!(
            words_to_entropy(typo).unwrap_err(),
            "word 5 is not a BIP39 word"
        );
        let e = share_from_words(&format!("{} hunter2", ["abandon"; 23].join(" "))).unwrap_err();
        assert!(e.contains("word 24") && !e.contains("hunter2"), "{e}");
    }

    #[test]
    fn completing_typed_words() {
        assert_eq!(
            complete_word("add"),
            Some("add"),
            "an exact word beats the longer words it starts"
        );
        assert_eq!(complete_word("abando"), Some("abandon"));
        assert_eq!(complete_word("ab"), None, "too short");
        assert_eq!(
            complete_word("aba"),
            Some("abandon"),
            "the only word with this prefix"
        );
        assert_eq!(
            complete_word("adv"),
            None,
            "advance and advice: more than one"
        );
        assert_eq!(
            complete_word("  ABAND "),
            Some("abandon"),
            "case and surrounding spaces are forgiven"
        );
    }

    #[test]
    fn prefixes_list_what_can_follow() {
        assert_eq!(words_with_prefix("aba"), ["abandon"]);
        assert_eq!(words_with_prefix("add"), ["add", "addict", "address"]);
        assert_eq!(words_with_prefix("").len(), 2048);
        assert!(
            words_with_prefix("abx").is_empty(),
            "no word can follow: the key is refused"
        );
    }
}
