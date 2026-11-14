use backup_core::*;
use serde_json::Value;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn vectors() -> Vec<Value> {
    serde_json::from_str(include_str!("../../vectors.json")).unwrap()
}

fn arr(v: &str) -> [u8; 32] {
    unhex(v).unwrap().try_into().unwrap()
}

#[test]
fn reproduces_every_vector() {
    assert_eq!(include_str!("../wordlist.txt").split_whitespace().count(), 2048);
    let vectors = vectors();
    assert_eq!(vectors.len(), 3);
    for v in &vectors {
        let f = |k: &str| v[k].as_str().unwrap();
        let name = f("name");
        let record = unhex(f("record")).unwrap();
        let header = &record[..22];

        // Intermediate values first, so a failure says which step disagrees.
        let (argon, pad_a) = derive_pad_a(f("passphrase"), header).unwrap();
        assert_eq!(hex(&argon), f("argon2id_out"), "{name}: argon2id");
        assert_eq!(hex(&pad_a), f("pad_a"), "{name}: padA");
        let pad_b = derive_pad_b(&unhex(f("prf")).unwrap(), header).unwrap();
        assert_eq!(hex(&pad_b), f("pad_b"), "{name}: padB");
        assert_eq!(hex(&words_to_entropy(f("share_c_words")).unwrap()), f("share_c"), "{name}: share C words");
        assert_eq!(entropy_to_words(&unhex(f("share_c")).unwrap()), f("share_c_words"), "{name}: share C encoding");

        // Sealing with the vector's random bytes must rebuild the stored record byte for byte.
        let rnd = unhex(f("random")).unwrap();
        let mut off = 0;
        let mut take = |n: usize| {
            off += n;
            rnd[off - n..off].to_vec()
        };
        let entropy = words_to_entropy(f("mnemonic")).unwrap();
        let (sealed, share_c) = seal(header, &pad_a, &pad_b, &entropy, &mut take).unwrap();
        assert_eq!(hex(&sealed), f("record"), "{name}: seal");
        assert_eq!(hex(&share_c), f("share_c"), "{name}: share C");

        // Every pair opens it, through the pads (no Argon2) ...
        let (a, b, c) = (Some(arr(f("pad_a"))), Some(arr(f("pad_b"))), Some(arr(f("share_c"))));
        for (fs, used) in [
            (Factors { a, b, c: None }, "A+B"),
            (Factors { a, b: None, c }, "A+C"),
            (Factors { a: None, b, c }, "B+C"),
        ] {
            let (e, u) = unseal(&record, &fs).unwrap();
            assert_eq!((hex(&e), u.as_str()), (hex(&entropy), used), "{name}");
        }
        // ... and through the user-facing path, from the passphrase and the passkey secret.
        let prf = unhex(f("prf")).unwrap();
        let (words, used) = restore(&record, Some(f("passphrase")), None, Some(f("share_c_words"))).unwrap();
        assert_eq!((words.as_str(), used.as_str()), (f("mnemonic"), "A+C"), "{name}");
        let (words, used) = restore(&record, Some(f("passphrase")), Some(&prf), None).unwrap();
        assert_eq!((words.as_str(), used.as_str()), (f("mnemonic"), "A+B"), "{name}");
        let (words, used) = restore(&record, None, Some(&prf), Some(f("share_c_words"))).unwrap();
        assert_eq!((words.as_str(), used.as_str()), (f("mnemonic"), "B+C"), "{name}");

        // One wrong factor of three still works through the other pair; one factor alone, or two wrong, fails.
        let wrong = format!("{}x", f("passphrase"));
        let (_, used) = restore(&record, Some(&wrong), Some(&prf), Some(f("share_c_words"))).unwrap();
        assert_eq!(used, "B+C", "{name}: wrong passphrase, other pair still opens");
        assert!(restore(&record, Some(&wrong), None, Some(f("share_c_words"))).is_err(), "{name}: wrong passphrase");
        assert!(restore(&record, Some(f("passphrase")), None, Some(f("mnemonic"))).is_err(), "{name}: wrong share C");
        assert!(restore(&record, None, None, Some(f("share_c_words"))).unwrap_err().contains("need two"), "{name}: one factor");
        let mut tampered = record.clone();
        tampered[100] ^= 1;
        assert!(restore(&tampered, Some(f("passphrase")), None, Some(f("share_c_words"))).is_err(), "{name}: tampered");
    }
}

#[test]
fn passphrase_is_seven_words_from_the_list() {
    let list: Vec<&str> = include_str!("../wordlist.txt").split_whitespace().collect();
    let pass = new_passphrase(7, &mut os_random);
    let words: Vec<&str> = pass.split(' ').collect();
    assert!(words.len() == 7 && words.iter().all(|w| list.contains(w)));
    assert_ne!(pass, new_passphrase(7, &mut os_random));
    // Index = low 11 bits of each big-endian 16-bit pair: 0x0000 is word 0, 0x07ff the last, 0x0800 wraps to word 0.
    let mut fixed = |_| vec![0x00, 0x00, 0x07, 0xff, 0x08, 0x00];
    assert_eq!(new_passphrase(3, &mut fixed), format!("{} {} {}", list[0], list[2047], list[0]));
}

#[test]
fn complete_word_takes_exact_words_and_unique_prefixes() {
    assert_eq!(complete_word("abandon"), Some("abandon"));
    assert_eq!(complete_word("  ABA "), Some("abandon")); // case and spaces forgiven, unique prefix
    assert_eq!(complete_word("add"), Some("add")); // exact beats the longer words it starts
    assert_eq!(complete_word("acc"), None); // access, accident, account, accuse
    assert_eq!(complete_word("ab"), None); // too short to be safe
    assert_eq!(complete_word("augst"), None); // not a word, not a prefix
}

#[test]
fn seal_rejects_bad_entropy_length() {
    let pad = [0u8; 32];
    assert!(seal(&new_header(1024, 1, &[0; 16]), &pad, &pad, &[0; 17], &mut os_random).is_err());
}

#[test]
fn rejects_oversized_argon_memory() {
    let mut header = unhex("010000040001a0a1a2a3a4a5a6a7a8a9aaabacadaeaf").unwrap();
    header[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(derive_pad_a("x", &header).unwrap_err().contains("refusing"));
}
