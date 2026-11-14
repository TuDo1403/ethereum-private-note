use backup_core::v2::*;
use backup_core::{check_argon_cost, derive_pad_a, entropy_to_words, os_random, unhex, words_to_entropy};
use serde_json::{json, Value};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Deterministic "randomness": byte i is (step * i + start) mod 256. Not random, which is the point.
fn pattern(start: u8, step: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| (step as usize * i + start as usize) as u8).collect()
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Passphrase => "passphrase",
        Kind::Hardware => "hardware",
        Kind::Paper => "paper",
    }
}

fn arr(v: &Value) -> [u8; 32] {
    unhex(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

/// name, m, t, k, kinds, passphrase, entropy, random start, hardware secret start
type Spec = (&'static str, u32, u8, usize, &'static [Kind], &'static str, &'static str, u8, u8);
use Kind::{Hardware as H, Paper as P, Passphrase as S};

const SPECS: [Spec; 7] = [
    ("fast-2-of-3-12-words", 1024, 1, 2, &[S, H, P], "correct horse battery staple", "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", 0x03, 0x40),
    (
        "fast-3-of-5-24-words-unicode-passphrase",
        1024,
        1,
        3,
        &[S, H, H, P, P],
        "ﬁancé ① pass phrase",
        "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
        0x05,
        0x50,
    ),
    ("fast-2-of-2-no-paper", 1024, 1, 2, &[S, H], "correct horse battery staple", "00112233445566778899aabbccddeeff", 0x07, 0x60),
    ("real-parameters-2-of-3-12-words", 1 << 20, 3, 2, &[S, H, P], "correct horse battery staple", "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", 0x03, 0x40),
    // k >= 4 pins the Lagrange weights for 4 and 5 points; all-paper is a valid record with no masked shares.
    ("fast-4-of-5-24-bytes", 1024, 1, 4, &[S, H, H, P, P], "correct horse battery staple", "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", 0x09, 0x70),
    ("fast-5-of-5-20-bytes", 1024, 1, 5, &[S, H, H, P, P], "correct horse battery staple", "000102030405060708090a0b0c0d0e0f10111213", 0x0b, 0x80),
    ("fast-3-of-4-all-paper", 1024, 1, 3, &[P, P, P, P], "", "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", 0x0d, 0x90),
];

/// Everything in a vector is derived from the Spec by the code under test, so regenerating is only
/// meaningful when the format changes on purpose. Run:
///   cargo test --offline --locked -p backup-core --test vectors_v2 -- --ignored generate
#[test]
#[ignore]
fn generate() {
    let mut out = Vec::new();
    for (name, m, t, k, kinds, passphrase, entropy, rnd, hw) in SPECS {
        let header = new_header(m, t, &pattern(0xa0, 1, 16), k, kinds).unwrap();
        let has_pass = kinds.contains(&S);
        let argon = if has_pass { stretch_passphrase(passphrase, &header).unwrap() } else { [0; 32] };
        let random = pattern(rnd, 7, 32 * k + 12);
        let mut off = 0;
        let mut take = |n: usize| {
            off += n;
            random[off - n..off].to_vec()
        };
        let entropy = unhex(entropy).unwrap();
        let mut shares = Vec::new();
        let mut pads = Vec::new();
        for (i, kind) in kinds.iter().enumerate() {
            let x = i as u8 + 1;
            match kind {
                Kind::Passphrase => pads.push((x, pad(&argon, &header, x))),
                Kind::Hardware => pads.push((x, pad(&pattern(hw + x, 1, 32), &header, x))),
                Kind::Paper => {}
            }
        }
        let (record, paper) = seal(&header, &pads, &entropy, &mut take).unwrap();
        for (i, kind) in kinds.iter().enumerate() {
            let x = i as u8 + 1;
            shares.push(match kind {
                Kind::Passphrase => json!({"x": x, "kind": kind_name(*kind), "pad": hex(&pads.iter().find(|p| p.0 == x).unwrap().1)}),
                Kind::Hardware => json!({"x": x, "kind": kind_name(*kind), "secret": hex(&pattern(hw + x, 1, 32)),
                    "pad": hex(&pads.iter().find(|p| p.0 == x).unwrap().1)}),
                Kind::Paper => {
                    let share = paper.iter().find(|p| p.0 == x).unwrap().1;
                    json!({"x": x, "kind": kind_name(*kind), "share": hex(&share), "words": entropy_to_words(&share)})
                }
            });
        }
        out.push(json!({
            "name": name, "k": k, "passphrase": passphrase, "mnemonic": entropy_to_words(&entropy),
            "entropy": hex(&entropy), "header": hex(&header), "random": hex(&random),
            "argon2id_out": has_pass.then(|| hex(&argon)), "shares": shares, "record": hex(&record),
        }));
    }
    std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors-v2.json"), serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
}

fn vectors() -> Vec<Value> {
    // Read at run time, not include_str!, so `generate` can build before the file exists.
    serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors-v2.json")).unwrap()).unwrap()
}

#[test]
fn reproduces_every_vector() {
    let vectors = vectors();
    assert_eq!(vectors.len(), SPECS.len());
    for v in &vectors {
        let f = |k: &str| v[k].as_str().unwrap();
        let name = f("name");
        let record = unhex(f("record")).unwrap();
        let h = parse_header(&record).unwrap();
        let header = &record[..h.len()];
        assert_eq!(hex(header), f("header"), "{name}");
        assert_eq!(h.k, v["k"].as_u64().unwrap() as usize, "{name}");
        assert_eq!(record.len(), h.record_len(), "{name}: layout");

        // Intermediate values first, so a failure says which step disagrees.
        let has_pass = h.kinds.contains(&S);
        let argon = if has_pass { stretch_passphrase(f("passphrase"), header).unwrap() } else { [0; 32] };
        assert_eq!(has_pass.then(|| hex(&argon)).as_deref(), v["argon2id_out"].as_str(), "{name}: argon2id");
        // Pads of on-chain shares and shares of paper shares, by x; plus the raw factors a person holds.
        let (mut factors, mut hardware, mut paper) = (Vec::new(), Vec::new(), Vec::new());
        for s in v["shares"].as_array().unwrap() {
            let x = s["x"].as_u64().unwrap() as u8;
            assert_eq!(s["kind"].as_str().unwrap(), kind_name(h.kinds[x as usize - 1]), "{name}: kind of {x}");
            match s["kind"].as_str().unwrap() {
                "passphrase" => {
                    assert_eq!(hex(&pad(&argon, header, x)), s["pad"].as_str().unwrap(), "{name}: pad {x}");
                    factors.push((x, arr(&s["pad"])));
                }
                "hardware" => {
                    let secret = arr(&s["secret"]);
                    assert_eq!(hex(&pad(&secret, header, x)), s["pad"].as_str().unwrap(), "{name}: pad {x}");
                    factors.push((x, arr(&s["pad"])));
                    hardware.push((x, secret));
                }
                _ => {
                    let words = s["words"].as_str().unwrap();
                    assert_eq!(hex(&words_to_entropy(words).unwrap()), s["share"].as_str().unwrap(), "{name}: words {x}");
                    assert_eq!(entropy_to_words(&arr(&s["share"])), words, "{name}: encoding {x}");
                    factors.push((x, arr(&s["share"])));
                    paper.push((x, words));
                }
            }
        }

        // Sealing with the vector's random bytes rebuilds the record and the paper shares byte for byte.
        let rnd = unhex(f("random")).unwrap();
        let mut off = 0;
        let mut take = |n: usize| {
            off += n;
            rnd[off - n..off].to_vec()
        };
        let entropy = unhex(f("entropy")).unwrap();
        let pads: Vec<_> = factors.iter().filter(|(x, _)| h.kinds[*x as usize - 1] != Kind::Paper).copied().collect();
        let (sealed, sealed_paper) = seal(header, &pads, &entropy, &mut take).unwrap();
        assert_eq!(hex(&sealed), f("record"), "{name}: seal");
        assert_eq!(off, rnd.len(), "{name}: all random bytes used");
        for (x, share) in &sealed_paper {
            assert!(factors.contains(&(*x, *share)), "{name}: paper share {x}");
        }

        // Every subset of size k or more of all n factors opens it, through the pads (no Argon2).
        let n = factors.len();
        for mask in 1u32..1 << n {
            let subset: Vec<_> = (0..n).filter(|i| mask >> i & 1 == 1).map(|i| factors[i]).collect();
            let r = unseal(&record, &subset);
            if subset.len() >= h.k {
                let (e, used) = r.unwrap_or_else(|e| panic!("{name}: subset {mask:b}: {e}"));
                assert_eq!(hex(&e), f("entropy"), "{name}");
                assert_eq!(used.len(), h.k, "{name}");
            } else {
                // Fewer than k factors: a clear error, never a wrong answer.
                assert!(r.unwrap_err().contains("need at least"), "{name}: {mask:b}");
            }
        }

        // One wrong factor among extras still works: corrupt the first factor, give all n.
        if n > h.k {
            let mut bad = factors.clone();
            bad[0].1[0] ^= 1;
            let (e, used) = unseal(&record, &bad).unwrap();
            assert_eq!(hex(&e), f("entropy"), "{name}: wrong factor among extras");
            assert!(!used.contains(&1), "{name}");
        }
        // ... and k factors with one wrong cannot open it.
        let mut bad: Vec<_> = factors[..h.k].to_vec();
        bad[0].1[0] ^= 1;
        assert!(unseal(&record, &bad).unwrap_err().contains("decryption failed"), "{name}: k with one wrong");

        // Tampering with the header (k, n, a kind, m, t, salt, version) never opens the record.
        for i in 0..h.len() {
            let mut t = record.clone();
            t[i] ^= 1;
            assert!(unseal(&t, &factors).is_err(), "{name}: header byte {i}");
        }
        // Tampering with k alone, to another valid value, passes parsing and must fail on the tag.
        let mut t = record.clone();
        t[22] = if h.k == 2 { 3.min(n as u8) } else { 2 };
        if t[22] as usize != h.k {
            assert!(unseal(&t, &factors).unwrap_err().contains("decryption failed"), "{name}: k tampered");
        }
        // Swapping two kinds of equal on-chain-ness changes only the AAD (layout stays valid).
        if h.kinds[0] == Kind::Passphrase && h.kinds[1] == Kind::Hardware {
            let mut t = record.clone();
            t[24..26].swap(0, 1);
            assert!(unseal(&t, &factors).unwrap_err().contains("decryption failed"), "{name}: kinds swapped");
        }
        // Tampering with the ciphertext and nonce fails too.
        for i in [record.len() - 1, record.len() - 49, record.len() - 61] {
            let mut t = record.clone();
            t[i] ^= 1;
            assert!(unseal(&t, &factors).is_err(), "{name}: byte {i}");
        }

        // The user-facing path: passphrase + hardware secrets + paper words.
        let pass = has_pass.then(|| f("passphrase"));
        let (words, used) = restore(&record, pass, &hardware, &paper).unwrap();
        assert_eq!((words.as_str(), used.len()), (f("mnemonic"), h.k), "{name}");
        // Without the passphrase (no Argon2): whatever else is held, if that is enough.
        if hardware.len() + paper.len() >= h.k {
            let (words, _) = restore(&record, None, &hardware, &paper).unwrap();
            assert_eq!(words, f("mnemonic"), "{name}: without passphrase");
        }
        // Too few, a factor at an x of the wrong kind, and the same factor twice.
        assert!(restore(&record, None, &[], &paper[..1.min(paper.len())]).unwrap_err().contains("need at least"), "{name}");
        if let Some(x) = h.kinds.iter().position(|&k| k != H) {
            assert!(restore(&record, None, &[(x as u8 + 1, [0; 32])], &[]).unwrap_err().contains("not a hardware share"), "{name}");
        }
        if let Some(x) = h.kinds.iter().position(|&k| k != P) {
            assert!(restore(&record, None, &[], &[(x as u8 + 1, "abandon")]).unwrap_err().contains("not a paper share"), "{name}");
        }
        if let Some(&(x, _)) = hardware.first() {
            assert!(restore(&record, None, &[(x, [0; 32]), (x, [0; 32])], &[]).unwrap_err().contains("twice"), "{name}");
        }
        // A bad paper share is refused before any work, and the words typed are not repeated.
        if let Some(&(x, _)) = paper.first() {
            let e = restore(&record, None, &[], &[(x, "hunter2secret abandon")]).unwrap_err();
            assert!(e.contains("paper share") && !e.contains("hunter2"), "{name}: {e}");
        }
    }
}

#[test]
fn presets_have_the_documented_layout() {
    let salt = [9u8; 16];
    let h = parse_header(&header_2_of_3(1024, 1, &salt)).unwrap();
    assert_eq!((h.k, h.kinds.as_slice(), h.record_len()), (2, &[S, H, P][..], 152));
    let h = parse_header(&header_3_of_5(1024, 1, &salt)).unwrap();
    assert_eq!((h.k, h.kinds.as_slice(), h.record_len()), (3, &[S, H, H, P, P][..], 186));
}

#[test]
fn header_validation() {
    let salt = [0u8; 16];
    assert!(new_header(1024, 1, &salt, 1, &[S, H]).is_err(), "k >= 2");
    assert!(new_header(1024, 1, &salt, 3, &[S, H]).is_err(), "k <= n");
    assert!(new_header(1024, 1, &salt, 2, &[P; 6]).is_err(), "n <= 5");
    assert!(new_header(1024, 1, &salt, 2, &[S, S, P]).is_err(), "one passphrase at most");
    assert!(new_header(1024, 1, &salt, 5, &[S, H, H, P, P]).is_ok(), "5-of-5");
    // An untrusted record cannot make us allocate by its own number.
    let mut header = header_2_of_3(1024, 1, &salt);
    header[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(stretch_passphrase("x", &header).unwrap_err().contains("refusing"));
}

#[test]
fn seal_checks_its_inputs() {
    let header = header_2_of_3(1024, 1, &[0; 16]);
    let pad = [1u8; 32];
    assert!(seal(&header, &[(1, pad), (2, pad)], &[0; 17], &mut os_random).is_err(), "entropy length");
    assert!(seal(&header, &[(1, pad)], &[0; 16], &mut os_random).is_err(), "missing pad");
    assert!(seal(&header, &[(1, pad), (2, pad), (3, pad)], &[0; 16], &mut os_random).is_err(), "pad for paper share");
    // Round trip with real randomness: the self-check a caller does right after sealing.
    let (record, paper) = seal(&header, &[(1, pad), (2, [2; 32])], &[7; 16], &mut os_random).unwrap();
    assert_eq!(paper.len(), 1);
    assert_eq!(unseal(&record, &[(1, pad), (2, [2; 32])]).unwrap().0, vec![7; 16]);
    assert_eq!(unseal(&record, &[(3, paper[0].1), (2, [2; 32])]).unwrap().0, vec![7; 16]);
}

#[test]
fn pads_differ_by_share_and_by_header() {
    let (h1, h2) = (header_2_of_3(1024, 1, &[1; 16]), header_2_of_3(1024, 1, &[2; 16]));
    let secret = [5u8; 32];
    assert_ne!(pad(&secret, &h1, 1), pad(&secret, &h1, 2));
    assert_ne!(pad(&secret, &h1, 2), pad(&secret, &h2, 2));
}

#[test]
fn argon_cost_bounds() {
    assert!(check_argon_cost(8, 1).is_ok());
    assert!(check_argon_cost(1 << 21, 16).is_ok(), "the caps themselves are allowed");
    for (m, t) in [(7, 1), (1024, 0), ((1 << 21) + 1, 1), (1024, 17), (u32::MAX, 255)] {
        assert!(check_argon_cost(m, t).is_err(), "m={m} t={t}");
    }
    assert!(check_argon_cost((1 << 21) + 1, 1).unwrap_err().contains("refusing"));
    assert!(check_argon_cost(1024, 17).unwrap_err().contains("refusing"));
    // Both formats refuse before doing any work.
    assert!(new_header(1024, 17, &[0; 16], 2, &[S, H]).is_err());
    assert!(new_header(1 << 22, 1, &[0; 16], 2, &[S, H]).is_err());
    let v1 = backup_core::new_header(1024, 17, &[0; 16]);
    assert!(derive_pad_a("x", &v1).unwrap_err().contains("refusing"));
    // t = 16 at the smallest memory runs (fast), so the cap is inclusive in practice too.
    assert!(derive_pad_a("x", &backup_core::new_header(8, 16, &[0; 16])).is_ok());
}

#[test]
fn malformed_headers_and_records_are_refused() {
    let header = header_2_of_3(1024, 1, &[0; 16]);
    let pads = [(1, [1u8; 32]), (2, [2u8; 32])];
    let (record, paper) = seal(&header, &pads, &[7; 16], &mut os_random).unwrap();
    let all = [pads[0], pads[1], paper[0]];
    assert!(unseal(&record, &all).is_ok());

    // Truncated or extended by one byte, at any end: not a record, never a panic.
    assert!(unseal(&record[..record.len() - 1], &all).is_err());
    assert!(unseal(&[&record[..], &[0]].concat(), &all).is_err());
    assert!(unseal(&record[1..], &all).is_err());
    for len in [0, 1, 23, 24, 26, 27, 100, 151] {
        assert!(unseal(&record[..len], &all).is_err(), "len {len}");
        assert!(restore(&record[..len], None, &[], &[]).is_err(), "len {len}");
    }

    let with = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut h = header.clone();
        edit(&mut h);
        parse_header(&h)
    };
    assert!(with(&|_| {}).is_ok());
    assert!(with(&|h| h[0] = 1).is_err(), "version");
    assert!(with(&|h| h[24] = 9).is_err(), "unknown kind byte");
    assert!(with(&|h| h[24] = 0).is_err(), "kind 0");
    assert!(with(&|h| h[22] = 0).is_err(), "k = 0");
    assert!(with(&|h| h[22] = 1).is_err(), "k = 1");
    assert!(with(&|h| h[22] = 4).is_err(), "k > n");
    assert!(with(&|h| h[23] = 0).is_err(), "n = 0");
    assert!(with(&|h| { h[23] = 6; h.extend([2, 3, 3]) }).is_err(), "n = 6");
    assert!(with(&|h| h[23] = 4).is_err(), "n larger than the kinds present");
    assert!(with(&|h| h[24..27].copy_from_slice(&[1, 1, 3])).is_err(), "two passphrase shares");
    assert!(with(&|h| h.truncate(23)).is_err(), "short buffer");
    assert!(with(&|h| h.truncate(25)).is_err(), "kinds cut short");
    assert!(parse_header(&[]).is_err());

    // Factors at x = 0, x > n, and the same x twice.
    assert!(unseal(&record, &[(0, [0; 32]), pads[0], pads[1]]).is_err());
    assert!(unseal(&record, &[(4, [0; 32]), pads[0], pads[1]]).is_err());
    assert!(unseal(&record, &[(255, [0; 32]), pads[0], pads[1]]).is_err());
    assert!(unseal(&record, &[pads[0], pads[0], pads[1]]).unwrap_err().contains("twice"));
}
