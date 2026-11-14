use base64ct::Encoding;
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn cli(args: &[&str], stdin: &str) -> Output {
    cli_path(args, stdin, &std::env::var("PATH").unwrap_or_default())
}

fn cli_path(args: &[&str], stdin: &str, path: &str) -> Output {
    // The dev machine running the tests is usually online; the host check has its own tests in epn-core.
    let mut child = Command::new(env!("CARGO_BIN_EXE_recover"))
        .args(args)
        .arg("--allow-unsafe-host")
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

/// The fast 3-of-5 vector with a unicode passphrase: passphrase (1), YubiKeys (2, 3), paper (4, 5).
fn vector() -> Value {
    let vectors: Vec<Value> = serde_json::from_str(include_str!("../../vectors.json")).unwrap();
    vectors[1].clone()
}

fn share(v: &Value, x: usize, k: &str) -> String {
    v["shares"][x - 1][k].as_str().unwrap().to_string()
}

#[test]
fn restore_reads_one_factor_per_stdin_line() {
    let v = vector();
    let f = |k: &str| v[k].as_str().unwrap();
    let (hw2, hw3, p4) = (
        share(&v, 2, "secret"),
        share(&v, 3, "secret"),
        share(&v, 4, "words"),
    );

    // Any 3 factors, any order; blank lines, a trailing newline and CRLF line endings are fine.
    for input in [
        format!("pass {}\npaper 4 {p4}\nhw 2 {hw2}\n", f("passphrase")),
        format!("hw 3 {hw3}\n\npaper 4 {p4}\nhw 2 {hw2}"),
        format!("hw 3 {hw3}\r\npaper 4 {p4}\r\nhw 2 {hw2}\r\n"),
    ] {
        let out = cli(&["restore", f("record")], &input);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), f("mnemonic"));
    }
    // Secrets never come from argv, and nothing misplaced is echoed (stdout or stderr). An unknown flag is
    // just an unexpected argument.
    for args in [
        vec!["restore", f("record"), &p4],
        vec!["restore", f("record"), "--bogus-secret", &p4],
        vec!["restore", f("record"), "--cred-id", "Zm9v"],
    ] {
        let out = cli(&args, &format!("hw 2 {hw2}\n"));
        let all = String::from_utf8_lossy(&[out.stdout, out.stderr].concat()).to_string();
        assert!(!all.contains(&p4[..8]), "{args:?}");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
    // A malformed line is a usage error that names the line number but not its content.
    let out = cli(
        &["restore", f("record")],
        &format!("hw 2 {hw2}\nsecretword {hw3}\n"),
    );
    assert_eq!(out.status.code(), Some(2));
    let err = stderr(&out);
    assert!(err.contains("line 2") && !err.contains("secretword") && !err.contains(&hw3[..8]));
    // The usage tells people to run the command alone, not to put factors in it.
    let usage = stderr(&cli(&[], ""));
    assert!(
        usage.contains("never put a factor inside a command line")
            && usage.contains("vault restore"),
        "{usage}"
    );
}

#[test]
fn restore_never_repeats_stdin_and_checks_before_slow_work() {
    let v = vector();
    let rec = v["record"].as_str().unwrap();
    let (hw2, p4) = (share(&v, 2, "secret"), share(&v, 4, "words"));
    let good = format!("hw 2 {hw2}\n");
    let secret = "hunter2secret";
    let words = |first: &str| format!("{first} {}", vec!["abandon"; 23].join(" "));

    // One malformed line of each type, each carrying the secret text where a person would mistype it.
    let cases = [
        format!("{secret}\n"),                  // no tag at all
        format!("{secret} x\n"),                // unknown tag
        format!("paper 4 {}\n", words(secret)), // not a BIP39 word
        format!("paper 4 {secret}\n"),          // wrong word count
        format!("paper {secret} {p4}\n"),       // bad x
        format!("paper 4 {secret} {}\n", p4.split_once(' ').unwrap().1), // right count, one bad word
        format!("hw 2 {secret}\n"),                                      // not hex
        format!("hw {secret} {hw2}\n"),                                  // bad x
        format!("hw 2 {hw2}00{secret}\n"),                               // wrong length
        format!("pass a\npass {secret}\n"),                              // second passphrase
    ];
    for input in cases {
        let out = cli(&["restore", rec], &format!("{good}{input}"));
        let all =
            String::from_utf8_lossy(&[out.stdout.clone(), out.stderr.clone()].concat()).to_string();
        assert!(
            !all.contains("hunter2") && !all.contains(&p4[..4]),
            "{input:?} leaked: {all}"
        );
        assert_eq!(out.status.code(), Some(2), "{input:?}: {all}");
        assert!(all.contains("stdin line "), "{input:?}: {all}");
    }
    // A mistyped word is reported by line and kind only.
    let out = cli(
        &["restore", rec],
        &format!("{good}paper 4 {}\n", words(secret)),
    );
    assert!(stderr(&out).contains("stdin line 2: invalid paper share"));

    // A factor at a wrong or repeated x is refused (the x is a number, not a secret).
    for input in [
        format!("{good}hw 1 {hw2}\n"),
        format!("{good}hw 2 {hw2}\n"),
        format!("{good}paper 2 {p4}\n"),
    ] {
        assert_eq!(
            cli(&["restore", rec], &input).status.code(),
            Some(1),
            "{input:?}"
        );
    }
    // Too few factors: refused before the YubiKey is asked for (--key) or Argon2 starts (pass).
    let out = cli(&["restore", rec, "--key", "3=Zm9v"], &good);
    let err = stderr(&out);
    assert!(
        out.status.code() == Some(1) && err.contains("need at least 3") && !err.contains("PIN"),
        "{err}"
    );
    let out = cli(
        &["restore", rec],
        &format!("pass {}\n", v["passphrase"].as_str().unwrap()),
    );
    let err = stderr(&out);
    assert!(
        out.status.code() == Some(1)
            && err.contains("need at least 3")
            && !err.contains("Stretching"),
        "{err}"
    );
    // Another version byte is refused.
    let out = cli(&["restore", &format!("02{}", &rec[2..])], &good);
    assert!(
        out.status.code() == Some(1) && stderr(&out).contains("unknown record version 2"),
        "{}",
        stderr(&out)
    );
}

fn base64(b: &[u8]) -> String {
    base64ct::Base64::encode_string(b)
}

/// A directory holding a fake `fido2-assert` that runs `body` (sh), put first on PATH. It stands in for
/// the YubiKey, which tests cannot touch. Returns (dir, PATH value).
fn fake_fido(name: &str, body: &str) -> (std::path::PathBuf, String) {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("epn-recover-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let tool = dir.join("fido2-assert");
    std::fs::write(&tool, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    (dir, path)
}

#[test]
fn yubikey_output_is_parsed_strictly() {
    let v = vector();
    let f = |k: &str| v[k].as_str().unwrap();
    let (hw2, hw3, p4) = (
        share(&v, 2, "secret"),
        share(&v, 3, "secret"),
        share(&v, 4, "words"),
    );
    let prf = epn_core::unhex(&hw2).unwrap();
    let args = [
        "restore",
        f("record"),
        "--key",
        "2=Zm9v",
        "--device",
        "/dev/null",
    ];
    let stdin = format!("hw 3 {hw3}\npaper 4 {p4}\n");
    // Echoes the client data hash and rp id it was sent, as libfido2 does, then auth data, signature, secret.
    let fake = |secret: &str| {
        format!(
            "read h; read rp; read id; read salt; printf '%s\\n' \"$h\" \"$rp\" AQID AQID {secret}"
        )
    };
    let (dir, path) = fake_fido("good", &fake(&base64(&prf)));
    let out = cli_path(&args, &stdin, &path);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), f("mnemonic"));
    std::fs::remove_dir_all(dir).unwrap();
    // A bad credential id is refused before the YubiKey is asked for its PIN.
    let out = cli(&["restore", f("record"), "--key", "2=!!bad"], &stdin);
    let err = stderr(&out);
    assert!(
        out.status.code() == Some(1) && err.contains("base64") && !err.contains("PIN"),
        "{err}"
    );
    // Output that is not a full assertion (only the client data hash, a zero or a short secret) never becomes
    // the hardware secret.
    for (name, body) in [
        ("one-line", "read h; echo \"$h\"".to_string()),
        ("zero-secret", fake(&base64(&[0; 32]))),
        ("short-secret", fake(&base64(&prf[..31]))),
    ] {
        let (dir, path) = fake_fido(name, &body);
        let out = cli_path(&args, &stdin, &path);
        let err = stderr(&out);
        assert_eq!(out.status.code(), Some(1), "{name}: {err}");
        assert!(err.contains("fido2-assert"), "{name}: {err}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn each_key_may_name_its_device() {
    let v = vector();
    let f = |k: &str| v[k].as_str().unwrap();
    let (prf2, prf3) = (
        base64(&epn_core::unhex(&share(&v, 2, "secret")).unwrap()),
        base64(&epn_core::unhex(&share(&v, 3, "secret")).unwrap()),
    );
    // The fake key answers with the secret of the share whose device path is its last argument (`-p PATH`).
    let (dir, path) = fake_fido(
        "devices",
        &format!(
            "for a; do dev=$a; done; read h; read rp; read id; read salt
case $dev in /dev/keyA) s={prf2};; /dev/keyB) s={prf3};; *) exit 1;; esac
printf '%s\\n' \"$h\" \"$rp\" AQID AQID \"$s\""
        ),
    );
    let stdin = format!("paper 4 {}\n", share(&v, 4, "words"));
    let args = [
        "restore",
        f("record"),
        "--key",
        "2=Zm9v@/dev/keyA",
        "--key",
        "3=YmFy@/dev/keyB",
    ];
    let out = cli_path(&args, &stdin, &path);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), f("mnemonic"));
    // A path after `@` wins over --device for that key; a key without one still uses --device.
    let mixed = [&args[..4], &["--key", "3=YmFy", "--device", "/dev/keyB"]].concat();
    let out = cli_path(&mixed, &stdin, &path);
    assert!(out.status.success(), "{}", stderr(&out));
    let mixed = [&args[..], &["--device", "/dev/nothing"]].concat();
    let out = cli_path(&mixed, &stdin, &path);
    assert!(out.status.success(), "{}", stderr(&out));
    std::fs::remove_dir_all(dir).unwrap();
    // An empty path after `@` is a usage error, not "auto-detect"; so is an empty credential id before it.
    for key in ["2=Zm9v@", "2=@/dev/keyA"] {
        let out = cli(&["restore", f("record"), "--key", key], &stdin);
        assert_eq!(out.status.code(), Some(2), "{key}: {}", stderr(&out));
        assert!(stderr(&out).contains("--key"), "{key}: {}", stderr(&out));
    }
}
