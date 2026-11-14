//! The reference implementation of ../SPEC.md. `tests/vectors.rs` rebuilds every record in ../vectors.json
//! byte for byte, which is the evidence the format is portable: an implementation in another language is
//! correct if it reproduces the same vectors.
//!
//! - `record`: the format itself: header, pads, k-of-n sealing and opening.
//! - `shamir`: GF(2^8) arithmetic and polynomial shares (private to this crate).
//! - `bip39`: the English word list, as seed words, paper shares and the generated passphrase.
//! - `fido`: the hardware secret from a YubiKey through libfido2's command-line tools.

pub mod bip39;
pub mod fido;
pub mod record;
mod shamir;

use sha2::{Digest, Sha256};

pub use hex::encode as hex;

/// Hex with an optional `0x` and surrounding whitespace.
pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| "not a hex string".into())
}

/// OS randomness. Failing loudly is the only safe answer: a backup made with bad randomness is worse than none.
pub fn os_random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("the OS random source failed; refusing to continue");
    b
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_and_record_id() {
        // A checksum-valid typo ("wave" -> "wage") gives another seed; the fingerprint shows it.
        let seed = bip39::words_to_entropy(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap();
        let typo = bip39::words_to_entropy(
            "legal winner thank year wage sausage worth useful legal winner thank yellow",
        )
        .unwrap();
        assert_eq!(seed_fingerprint(&seed), "87dcde7f");
        assert_eq!(seed_fingerprint(&typo), "8b4cedd3");
        assert_eq!(record_id(b""), "e3b0c44298fc1c14"); // SHA-256("") starts e3b0c442 98fc1c14
    }

    #[test]
    fn unhex_is_strict() {
        assert_eq!(unhex(" 0x00ff\n").unwrap(), [0, 255]);
        for bad in ["0", "zz", "+f", "-1", "0x+1", "é0"] {
            assert!(unhex(bad).is_err(), "{bad}");
        }
    }
}
