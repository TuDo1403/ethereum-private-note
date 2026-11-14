use serde_json::Value;
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn cli(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_recover"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn restore_takes_secrets_from_stdin_only() {
    let vectors: Vec<Value> = serde_json::from_str(include_str!("../../vectors.json")).unwrap();
    let v = &vectors[0]; // fast parameters
    let f = |k: &str| v[k].as_str().unwrap();

    for input in [format!("{}\n{}\n", f("share_c_words"), f("passphrase")), format!("{}\n{}", f("share_c_words"), f("passphrase"))] {
        let out = cli(&["restore", f("record")], &input);
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), f("mnemonic"));
    }
    // Share C on the command line is refused, so it can never leak through argv, and is never echoed.
    let out = cli(&["restore", f("record"), f("share_c_words")], f("passphrase"));
    assert_eq!(out.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("diamond"));
    // No newline between share C and passphrase: usage error, not a guess at where one ends.
    assert_eq!(cli(&["restore", f("record")], f("passphrase")).status.code(), Some(2));
    // A single factor is not enough, and an empty first line means "no share C".
    let out = cli(&["restore", f("record")], &format!("\n{}\n", f("passphrase")));
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("need two"));
    // Only `restore` exists here: backups are made with `vault`.
    assert_eq!(cli(&[f("record")], "").status.code(), Some(2));
    assert_eq!(cli(&["backup"], "").status.code(), Some(2));
}

#[test]
fn restore_v2_reads_one_factor_per_stdin_line() {
    let vectors: Vec<Value> = serde_json::from_str(include_str!("../../vectors-v2.json")).unwrap();
    // fast 3-of-5 with a unicode passphrase: passphrase (1), YubiKeys (2, 3), paper (4, 5).
    let v = &vectors[1];
    let f = |k: &str| v[k].as_str().unwrap();
    let share = |x: usize, k: &str| v["shares"][x - 1][k].as_str().unwrap().to_string();
    let (hw2, hw3, p4) = (share(2, "secret"), share(3, "secret"), share(4, "words"));

    // Any 3 factors, any order, blank lines and a trailing newline are fine.
    for input in [
        format!("pass {}\npaper 4 {p4}\nhw 2 {hw2}\n", f("passphrase")),
        format!("hw 3 {hw3}\n\npaper 4 {p4}\nhw 2 {hw2}"),
    ] {
        let out = cli(&["restore", f("record")], &input);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), f("mnemonic"));
    }
    // Two factors are fewer than k: a clear error. A wrong factor among enough still works.
    let out = cli(&["restore", f("record")], &format!("hw 2 {hw2}\npaper 4 {p4}\n"));
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("need at least 3"));
    let wrong = "00".repeat(32);
    let out = cli(&["restore", f("record")], &format!("hw 2 {hw2}\nhw 3 {hw3}\npaper 4 {p4}\nhw 1 {wrong}\n"));
    assert_eq!(out.status.code(), Some(1), "x=1 is the passphrase share, not a hardware share");
    // Secrets never come from argv, and nothing misplaced is echoed (stdout or stderr).
    for args in [vec!["restore", f("record"), &p4], vec!["restore", f("record"), "--bogus-secret", &p4]] {
        let out = cli(&args, &format!("hw 2 {hw2}\n"));
        let all = [out.stdout, out.stderr].concat();
        assert!(!String::from_utf8_lossy(&all).contains(&p4[..8]), "{args:?}");
        assert_eq!(out.status.code(), Some(2));
    }
    // A malformed line is a usage error that names the line number but not its content.
    let out = cli(&["restore", f("record")], &format!("hw 2 {hw2}\nsecretword {hw3}\n"));
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(err.contains("line 2") && !err.contains("secretword") && !err.contains(&hw3[..8]));
    // --key is for v2 only: a v1 record with it is a usage error.
    let v1: Vec<Value> = serde_json::from_str(include_str!("../../vectors.json")).unwrap();
    assert_eq!(cli(&["restore", v1[0]["record"].as_str().unwrap(), "--key", "1=a"], "").status.code(), Some(2));
}

#[test]
fn restore_v2_never_repeats_stdin_and_checks_before_slow_work() {
    let vectors: Vec<Value> = serde_json::from_str(include_str!("../../vectors-v2.json")).unwrap();
    let v = &vectors[1]; // 3-of-5: passphrase (1), YubiKeys (2, 3), paper (4, 5)
    let rec = v["record"].as_str().unwrap();
    let share = |x: usize, k: &str| v["shares"][x - 1][k].as_str().unwrap().to_string();
    let (hw2, p4) = (share(2, "secret"), share(4, "words"));
    let good = format!("hw 2 {hw2}\n");
    let secret = "hunter2secret";
    let words = |first: &str| format!("{first} {}", vec!["abandon"; 23].join(" "));

    // One malformed line of each type, each carrying the secret text where a person would mistype it.
    let cases = [
        format!("{secret}\n"),                          // no tag at all
        format!("{secret} x\n"),                        // unknown tag
        format!("paper 4 {}\n", words(secret)),         // not a BIP39 word
        format!("paper 4 {secret}\n"),                  // wrong word count
        format!("paper {secret} {p4}\n"),               // bad x
        format!("paper 4 {secret} {}\n", p4.split_once(' ').unwrap().1), // right count, one bad word
        format!("hw 2 {secret}\n"),                     // not hex
        format!("hw {secret} {hw2}\n"),                 // bad x
        format!("hw 2 {hw2}00{secret}\n"),              // wrong length
        format!("pass a\npass {secret}\n"),             // second passphrase
    ];
    for input in cases {
        let out = cli(&["restore", rec], &format!("{good}{input}"));
        let all = String::from_utf8_lossy(&[out.stdout.clone(), out.stderr.clone()].concat()).to_string();
        assert!(!all.contains("hunter2") && !all.contains(&p4[..4]), "{input:?} leaked: {all}");
        assert_eq!(out.status.code(), Some(2), "{input:?}: {all}");
        assert!(all.contains("stdin line "), "{input:?}: {all}");
    }
    // The exact case the review found: a mistyped word is reported by line and kind only.
    let out = cli(&["restore", rec], &format!("{good}paper 4 {}\n", words(secret)));
    assert!(String::from_utf8_lossy(&out.stderr).contains("stdin line 2: invalid paper share"));

    // A factor at a wrong or repeated x is refused (the x is a number, not a secret).
    for input in [format!("{good}hw 1 {hw2}\n"), format!("{good}hw 2 {hw2}\n"), format!("{good}paper 2 {p4}\n")] {
        assert_eq!(cli(&["restore", rec], &input).status.code(), Some(1), "{input:?}");
    }
    // Too few factors: refused before the YubiKey is asked for (--key) or Argon2 starts (pass).
    let out = cli(&["restore", rec, "--key", "3=Zm9v"], &format!("{good}"));
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.code() == Some(1) && err.contains("need at least 3") && !err.contains("PIN"), "{err}");
    let out = cli(&["restore", rec], &format!("pass {}\n", v["passphrase"].as_str().unwrap()));
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.code() == Some(1) && err.contains("need at least 3") && !err.contains("Stretching"), "{err}");
    // --cred-id is a v1 option and is refused for v2 instead of being ignored.
    let out = cli(&["restore", rec, "--cred-id", "Zm9v"], &good);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--key"));
}
