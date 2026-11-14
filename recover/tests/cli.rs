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
