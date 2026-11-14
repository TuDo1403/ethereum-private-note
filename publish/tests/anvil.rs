//! End-to-end against a local anvil. Skipped (with a message) when `anvil` is not installed.
use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256, address},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use epn_core::record_id;
use epn_publish::{FundRequest, Options, publish as run};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

// anvil's well-known, public dev account #0 (never holds real funds).
const DEV_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const REFUND: Address = address!("00000000000000000000000000000000000dEaD1");

struct Anvil(Child, String);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

async fn start_anvil() -> Option<Anvil> {
    start_anvil_with(&[]).await
}

async fn start_anvil_with(extra: &[&str]) -> Option<Anvil> {
    // The port is found by binding and releasing it, so a parallel test's anvil can take it first. Then ours
    // exits at startup (and a reachable port is not ours): start again on a new port.
    'start: for _ in 0..3 {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let child = match Command::new("anvil")
            .args(["--silent", "--port", &port.to_string()])
            .args(extra)
            .stdout(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => {
                eprintln!("anvil not installed: skipping");
                return None;
            }
        };
        let url = format!("http://127.0.0.1:{port}");
        let mut anvil = Anvil(child, url.clone());
        let p = ProviderBuilder::new().connect(&url).await.unwrap();
        // Tests start anvil in parallel and slow CI runners need up to 30 s; a healthy start returns early.
        for _ in 0..300 {
            let answered = p.get_chain_id().await.is_ok();
            if anvil.0.try_wait().unwrap().is_some() {
                continue 'start;
            }
            if answered {
                // A node that answers while ours is dying belongs to another test that took the port.
                tokio::time::sleep(Duration::from_millis(300)).await;
                if anvil.0.try_wait().unwrap().is_some() {
                    continue 'start;
                }
                return Some(anvil);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("anvil did not start within 30s");
    }
    panic!("anvil exited at startup three times");
}

/// One JSON-RPC call whose result is ignored (anvil's cheat codes). A macro because the parameter
/// bound, `alloy::rpc::json_rpc::RpcSend`, is behind an alloy feature this crate does not enable.
macro_rules! raw {
    ($url:expr, $method:expr, $params:expr) => {
        ProviderBuilder::new()
            .connect($url)
            .await
            .unwrap()
            .raw_request::<_, Option<String>>($method.into(), $params)
            .await
            .unwrap()
    };
}

async fn set_code(url: &str, who: Address, code: &str) {
    raw!(url, "anvil_setCode", (who, code));
}

/// Turn anvil's automatic mining on or off; `mine` mines one block now.
async fn automine(url: &str, on: bool) {
    raw!(url, "evm_setAutomine", (on,));
}

async fn mine(url: &str) {
    raw!(url, "evm_mine", ());
}

fn opts<'a>(url: &'a str) -> Options<'a> {
    Options {
        rpc_url: url,
        verify_rpc_url: None,
        refund: REFUND,
        fund_timeout: Duration::from_secs(30),
        confirmations: 1,
        allow_high_fees: false,
    }
}

fn dev(url: &str) -> impl Provider {
    let signer: PrivateKeySigner = DEV_KEY.parse().unwrap();
    ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(url.parse().unwrap())
}

async fn send_eth(url: &str, to: Address, wei: U256) {
    dev(url)
        .send_transaction(TransactionRequest::default().to(to).value(wei))
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
}

/// Fund `to` while automine is off: send, mine one block, wait for the receipt.
async fn send_eth_and_mine(url: &str, to: Address, wei: U256) {
    let pending = dev(url)
        .send_transaction(TransactionRequest::default().to(to).value(wei))
        .await
        .unwrap();
    mine(url).await;
    pending.get_receipt().await.unwrap();
}

/// Run the flow, funding the throwaway sender from the dev account whenever asked (`pct` of the ask).
async fn run_funded_opts(
    o: &Options<'_>,
    record: &[u8],
    pct: u64,
) -> Result<epn_publish::Outcome, String> {
    let url = o.rpc_url.to_string();
    run(o, record, move |r: &FundRequest| {
        let (url, to, wei) = (
            url.clone(),
            r.sender,
            r.required_wei * U256::from(pct) / U256::from(100),
        );
        tokio::spawn(async move { send_eth(&url, to, wei).await });
    })
    .await
}

async fn run_funded(url: &str, record: &[u8]) -> Result<epn_publish::Outcome, String> {
    run_funded_opts(&opts(url), record, 100).await
}

/// Make the next block's base fee `wei` and mine it, so the node's fee quote jumps.
async fn spike_base_fee(url: &str, wei: u128) {
    raw!(url, "anvil_setNextBlockBaseFeePerGas", (U256::from(wei),));
    mine(url).await;
}

/// A valid 2-of-3 record (version 1: passphrase, YubiKey, paper; m = 1024 KiB, t = 3), distinct per seed.
fn record(seed: u8) -> Vec<u8> {
    let mut r = vec![1, 0, 0, 4, 0, 3];
    r.extend([0; 16]); // salt
    r.extend([2, 3, 1, 2, 3]); // k, n, kinds
    r.extend((r.len()..152).map(|i| seed.wrapping_add(i as u8)));
    r
}

/// The largest record SPEC.md allows: 3-of-5, all five shares on chain (passphrase + 4 hardware).
fn largest_record() -> Vec<u8> {
    let mut r = vec![0x01, 0, 0x10, 0, 0, 3];
    r.resize(22, 0x5a); // salt
    r.extend([3, 5, 1, 2, 2, 2, 2]);
    r.resize(85 + 5 + 32 * 5, 0xc3);
    r
}

fn eth(n: u64) -> U256 {
    U256::from(n) * U256::from(10u64).pow(U256::from(16)) // n x 0.01 ETH
}

/// What a restore reads: the code at the address is `0x00 || record`.
async fn stored(p: &impl Provider, at: Address) -> Vec<u8> {
    let code = p.get_code_at(at).await.unwrap();
    assert_eq!(code.first(), Some(&0), "code must start with the STOP byte");
    code[1..].to_vec()
}

#[tokio::test(flavor = "multi_thread")]
async fn deploys_record_as_code_reads_back_and_sweeps() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    let p = ProviderBuilder::new().connect(&anvil.1).await.unwrap();

    // The largest record (250 bytes, code 251 bytes) deploys within the estimated gas.
    let rec = largest_record();
    assert_eq!(rec.len(), 250);
    let out = run_funded(&anvil.1, &rec).await.unwrap();
    assert_eq!(out.address, out.sender.create(0));
    assert!(out.swept > U256::ZERO);
    assert_eq!(p.get_balance(REFUND).await.unwrap(), out.swept);
    // Sender is drained to (almost) nothing: only the sweep's fee headroom may remain.
    assert!(p.get_balance(out.sender).await.unwrap() < eth(1));
    assert_eq!(stored(&p, out.address).await, rec);

    // Second run: new throwaway sender, new address; the first record is untouched.
    let rec2 = record(77);
    let out2 = run_funded(&anvil.1, &rec2).await.unwrap();
    assert_ne!(out.address, out2.address);
    assert_eq!(stored(&p, out2.address).await, rec2);
    assert_eq!(stored(&p, out.address).await, rec);
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_record_is_refused_before_funding() {
    let o = opts("http://127.0.0.1:1");
    let err = run(&o, &[0u8; 152], |_: &FundRequest| {
        panic!("must not ask for funds")
    })
    .await
    .unwrap_err();
    assert!(err.contains("version 0"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn refund_with_code_or_special_address_is_rejected_before_funding() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    set_code(&anvil.1, REFUND, "0x6000").await;
    let asked = Arc::new(Mutex::new(0));
    let a2 = asked.clone();
    let err = run(&opts(&anvil.1), &record(1), move |_: &FundRequest| {
        *a2.lock().unwrap() += 1
    })
    .await
    .unwrap_err();
    assert!(err.contains("has code"), "{err}");
    let mut o = opts(&anvil.1);
    o.refund = Address::ZERO;
    assert!(
        run(&o, &record(1), |_: &FundRequest| {})
            .await
            .unwrap_err()
            .contains("refund address must be")
    );
    assert_eq!(
        *asked.lock().unwrap(),
        0,
        "must fail before asking for funds"
    );
}

/// The read-back goes to the verify RPC (here the same node); the deploy needs 3 confirmations, so the
/// run must wait for two more blocks after it is mined.
#[tokio::test(flavor = "multi_thread")]
async fn second_rpc_verifies_and_confirmations_are_awaited() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    let p = ProviderBuilder::new().connect(&anvil.1).await.unwrap();
    let first = p.get_block_number().await.unwrap();
    let mut o = opts(&anvil.1);
    o.verify_rpc_url = Some(&anvil.1);
    o.confirmations = 3;
    let rec = record(9);
    let run_fut = run_funded_opts(&o, &rec, 100);
    tokio::pin!(run_fut);
    // Block `first + 1` is the funding, `first + 2` the deploy; the run must still be waiting 3 s later.
    let deploy_mined = async {
        while p.get_block_number().await.unwrap() < first + 2 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    };
    tokio::select! {
        r = &mut run_fut => panic!("returned before 3 confirmations: {r:?}"),
        () = deploy_mined => {}
    }
    mine(&anvil.1).await;
    mine(&anvil.1).await;
    tokio::time::timeout(Duration::from_secs(30), run_fut)
        .await
        .expect("run did not finish after the confirmations")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn funding_timeout_sweeps_partial_funds() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    let mut o = opts(&anvil.1);
    o.fund_timeout = Duration::from_secs(4);
    let err = run_funded_opts(&o, &record(1), 50).await.unwrap_err();
    assert!(err.contains("timed out") && err.contains("swept"), "{err}");
    assert!(err.contains("Do not send funds to"), "{err}");
    let p = ProviderBuilder::new().connect(&anvil.1).await.unwrap();
    assert!(p.get_balance(REFUND).await.unwrap() > U256::ZERO);
}

/// TCP pass-through to `target` that drops every connection (and every request on a kept-alive one)
/// while `down` is set: an RPC outage. Returns its URL, `down` and the count of requests it dropped.
fn flaky_proxy(target: &str) -> (String, Arc<AtomicBool>, Arc<AtomicUsize>) {
    let (down, dropped) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicUsize::new(0)),
    );
    let (down_out, dropped_out) = (down.clone(), dropped.clone());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let target = target.trim_start_matches("http://").to_string();
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            if down.load(SeqCst) {
                dropped.fetch_add(1, SeqCst);
                continue; // closes the connection
            }
            let server = TcpStream::connect(&target).unwrap();
            for (mut from, mut to) in [
                (client.try_clone().unwrap(), server.try_clone().unwrap()),
                (server, client),
            ] {
                let (down, dropped) = (down.clone(), dropped.clone());
                std::thread::spawn(move || {
                    let mut buf = [0u8; 16 * 1024];
                    while let Ok(n @ 1..) = from.read(&mut buf) {
                        if down.load(SeqCst) {
                            dropped.fetch_add(1, SeqCst);
                            break;
                        }
                        if to.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    let _ = from.shutdown(Shutdown::Both);
                    let _ = to.shutdown(Shutdown::Both);
                });
            }
        }
    });
    (url, down_out, dropped_out)
}

/// The RPC fails right after the funding address is shown and recovers only after the payment landed:
/// the run must keep polling instead of quitting with the payment in flight.
#[tokio::test(flavor = "multi_thread")]
async fn rpc_outage_during_funding_wait_is_retried() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    let (proxy, down, dropped) = flaky_proxy(&anvil.1);
    let (url, d2) = (anvil.1.clone(), down.clone());
    let rec = record(21);
    let out = run(&opts(&proxy), &rec, move |r: &FundRequest| {
        let (url, d2, to, wei) = (url.clone(), d2.clone(), r.sender, r.required_wei);
        d2.store(true, SeqCst);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await; // >= 2 failed polls
            send_eth(&url, to, wei).await; // straight to anvil, not through the proxy
            d2.store(false, SeqCst);
        });
    })
    .await
    .unwrap();
    assert!(dropped.load(SeqCst) >= 2, "the outage must have been hit");
    let p = ProviderBuilder::new().connect(&anvil.1).await.unwrap();
    assert_eq!(stored(&p, out.address).await, rec);
}

#[tokio::test(flavor = "multi_thread")]
async fn fees_are_requoted_after_funding() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    let (url, asks) = (anvil.1.clone(), Arc::new(Mutex::new(Vec::<U256>::new())));
    let a2 = asks.clone();
    run(&opts(&anvil.1), &record(3), move |r: &FundRequest| {
        let n = {
            let mut g = a2.lock().unwrap();
            g.push(r.required_wei);
            g.len()
        };
        let (url, to, wei) = (url.clone(), r.sender, r.required_wei);
        tokio::spawn(async move {
            // First ask: the price jumps 20x before the money arrives. Second ask: pay it.
            if n == 1 {
                spike_base_fee(&url, 20_000_000_000).await;
            }
            send_eth(&url, to, wei).await;
        });
    })
    .await
    .unwrap();
    let asks = asks.lock().unwrap();
    assert!(
        asks.len() >= 2 && asks[1] > asks[0],
        "expected a larger second ask, got {asks:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn absurd_fees_are_refused_before_funding() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    spike_base_fee(&anvil.1, 5_000_000_000_000).await; // 5000 gwei
    let err = run(&opts(&anvil.1), &record(1), |_: &FundRequest| {
        panic!("must not ask for funds")
    })
    .await
    .unwrap_err();
    assert!(err.contains("sanity cap"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn rpc_url_secret_is_not_leaked_in_errors() {
    // The second URL is printed by reqwest in its parsed (lowercased) form.
    for url in [
        "http://127.0.0.1:1/?key=SECRETKEY",
        "HTTP://LOCALHOST:1/SECRETKEY",
    ] {
        let o = Options {
            rpc_url: url,
            ..opts("")
        };
        let err = run(&o, &record(1), |_: &FundRequest| {}).await.unwrap_err();
        assert!(!err.to_lowercase().contains("secretkey"), "{err}");
    }
}

// ---- The `publish` binary: signals, printed output, arguments. ----

/// The binary with stdout and stderr merged into one line channel ("out: ..." / "err: ...").
struct Bin {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Bin {
    fn spawn(args: &[&str]) -> Bin {
        let mut child = Command::new(env!("CARGO_BIN_EXE_publish"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (tx, lines) = mpsc::channel();
        let pipes: [(&str, Box<dyn Read + Send>); 2] = [
            ("out", Box::new(child.stdout.take().unwrap())),
            ("err", Box::new(child.stderr.take().unwrap())),
        ];
        for (tag, pipe) in pipes {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                    let _ = tx.send(format!("{tag}: {line}"));
                }
            });
        }
        Bin {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    /// Block (up to 60 s) until a line containing `needle` appears; returns it.
    fn wait_for(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let line = self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|_| panic!("no line with {needle:?} in {:#?}", self.seen));
            self.seen.push(line.clone());
            if line.contains(needle) {
                return line;
            }
        }
    }

    /// (sender, wei) from the `ethereum:<sender>@<chain>?value=<wei>` funding line.
    fn funding_request(&mut self) -> (Address, U256) {
        let line = self.wait_for("ethereum:");
        let uri = line.split("ethereum:").nth(1).unwrap();
        (
            uri.split('@').next().unwrap().parse().unwrap(),
            uri.split("value=").nth(1).unwrap().trim().parse().unwrap(),
        )
    }

    fn interrupt(&self) {
        assert!(
            Command::new("kill")
                .args(["-INT", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }

    /// Wait (up to 120 s) for exit; returns (exit success, every output line).
    fn finish(mut self) -> (bool, String) {
        let deadline = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s;
            }
            assert!(
                Instant::now() < deadline,
                "publish did not exit: {:#?}",
                self.seen
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(5)) {
            self.seen.push(line);
        }
        (status.success(), self.seen.join("\n"))
    }
}

impl Drop for Bin {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// Write `rec` as a record.hex file; returns its path.
fn record_file(rec: &[u8], name: &str) -> String {
    let path = std::env::temp_dir().join(format!(
        "epn-publish-test-{}-{name}.hex",
        std::process::id()
    ));
    std::fs::write(&path, format!("0x{}\n", alloy::hex::encode(rec))).unwrap();
    path.to_string_lossy().into_owned()
}

fn printed_key(out: &str) -> Option<PrivateKeySigner> {
    out.lines()
        .find_map(|l| l.split("THROWAWAY PRIVATE KEY: ").nth(1))
        .map(|k| k.trim().parse().unwrap())
}

/// Ctrl-C while partly funded: the partial funds are swept, and because a payment may still arrive the
/// user is told not to send more and gets the throwaway key (which must control the sender).
#[tokio::test(flavor = "multi_thread")]
async fn binary_ctrl_c_while_waiting_sweeps_and_prints_key() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    let file = record_file(&record(11), "ctrlc-wait");
    let mut bin = Bin::spawn(&[&anvil.1, &file, &REFUND.to_string()]);
    let (sender, wei) = bin.funding_request();
    send_eth(&anvil.1, sender, wei / U256::from(2)).await;
    bin.interrupt();
    let (ok, out) = bin.finish();
    assert!(!ok, "{out}");
    assert!(
        out.contains("interrupted") && out.contains("Do not send funds to"),
        "{out}"
    );
    assert_eq!(
        printed_key(&out).expect("key must be printed").address(),
        sender
    );
    let p = ProviderBuilder::new().connect(&anvil.1).await.unwrap();
    assert!(
        p.get_balance(REFUND).await.unwrap() > wei / U256::from(3),
        "partial funds must be swept back"
    );
    assert!(p.get_balance(sender).await.unwrap() < eth(1));
}

/// The deploy is stuck in the mempool (mining off) when Ctrl-C arrives. The sweep must REPLACE it
/// (latest mined nonce 0, higher fee), not queue behind it; nothing is stored then.
#[tokio::test(flavor = "multi_thread")]
async fn binary_ctrl_c_with_stuck_deploy_sweep_replaces_it() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    let p = ProviderBuilder::new().connect(&anvil.1).await.unwrap();
    let file = record_file(&record(12), "stuck");
    let mut bin = Bin::spawn(&[&anvil.1, &file, &REFUND.to_string()]);
    let (sender, wei) = bin.funding_request();

    automine(&anvil.1, false).await;
    send_eth_and_mine(&anvil.1, sender, wei).await;
    bin.wait_for("deploy tx"); // sent, and never mined while mining is off
    bin.interrupt();
    bin.wait_for("sweep tx"); // accepted by the pool at the deploy's nonce
    mine(&anvil.1).await;
    let (ok, out) = bin.finish();

    assert!(
        !ok && out.contains("interrupted") && out.contains("swept"),
        "{out}"
    );
    assert!(
        p.get_code_at(sender.create(0)).await.unwrap().is_empty(),
        "the stuck deploy must be replaced, not mined: {out}"
    );
    assert_eq!(
        p.get_transaction_count(sender).await.unwrap(),
        1,
        "only the sweep was mined"
    );
    assert!(
        p.get_balance(REFUND).await.unwrap() > wei * U256::from(9) / U256::from(10),
        "{out}"
    );
    assert!(
        !out.contains("address:"),
        "nothing is stored, so no sheet: {out}"
    );
    assert!(
        printed_key(&out).is_none(),
        "funds arrived and were swept: the key must stay secret: {out}"
    );
}

/// Funds arrived, the deploy is stuck, and the fee quote jumps far above the sanity cap before the sweep.
/// The balance cannot pay for the sweep, which keeps retrying; a second Ctrl-C abandons it. The run must
/// then fail AND print the key (a sweep that reports "nothing to sweep" would let the run forget the only
/// key to that ETH), and name the address to check in case the deploy lands later.
#[tokio::test(flavor = "multi_thread")]
async fn binary_unsweepable_balance_keeps_the_key() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    let p = ProviderBuilder::new().connect(&anvil.1).await.unwrap();
    let file = record_file(&record(13), "unsweepable");
    let mut bin = Bin::spawn(&[&anvil.1, &file, &REFUND.to_string()]);
    let (sender, wei) = bin.funding_request();

    automine(&anvil.1, false).await;
    send_eth_and_mine(&anvil.1, sender, wei).await;
    bin.wait_for("deploy tx");
    spike_base_fee(&anvil.1, 5_000_000_000_000).await; // 5000 gwei: the deploy stays out of this block
    bin.interrupt();
    bin.wait_for("does not cover the sweep's fee"); // the sweep is retrying
    bin.interrupt();
    let (ok, out) = bin.finish();

    assert!(!ok && out.contains("interrupted again"), "{out}");
    assert!(
        out.contains(&format!("record is at {}", sender.create(0))),
        "{out}"
    );
    assert_eq!(
        printed_key(&out).expect("key must be printed").address(),
        sender,
        "{out}"
    );
    assert_eq!(
        p.get_balance(sender).await.unwrap(),
        wei,
        "nothing was spent: {out}"
    );
}

/// An RPC that accepts connections and never answers must not hold the run forever: every request is
/// bounded, so the run fails instead of hanging.
#[tokio::test(flavor = "multi_thread")]
async fn stalled_rpc_does_not_hang_the_run() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let held: Vec<TcpStream> = listener.incoming().flatten().collect(); // accept, never reply
        drop(held);
    });
    let start = Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(60),
        run(&opts(&url), &record(1), |_: &FundRequest| {}),
    )
    .await;
    let err = res.expect("run hung on a stalled RPC").unwrap_err();
    assert!(err.contains("chain id"), "{err}");
    assert!(
        start.elapsed() < Duration::from_secs(40),
        "{:?}",
        start.elapsed()
    );
}

/// Start the binary behind a flaky proxy, fund it, and let its deploy be mined while the RPC is down. It
/// returns with the RPC still down; the caller brings it back.
async fn deploy_mined_during_outage(
    anvil: &Anvil,
    rec: &[u8],
    name: &str,
) -> (Bin, Address, Arc<AtomicBool>, Arc<AtomicUsize>) {
    let (proxy, down, dropped) = flaky_proxy(&anvil.1);
    let file = record_file(rec, name);
    let mut bin = Bin::spawn(&[&proxy, &file, &REFUND.to_string()]);
    let (sender, wei) = bin.funding_request();

    automine(&anvil.1, false).await;
    send_eth_and_mine(&anvil.1, sender, wei).await;
    bin.wait_for("deploy tx");
    down.store(true, SeqCst); // the binary can no longer see the chain...
    mine(&anvil.1).await; // ...while its deploy is mined at nonce 0
    automine(&anvil.1, true).await;
    (bin, sender, down, dropped)
}

/// Nonce-0 race: the run gives up on a deploy it could not see confirmed (here: RPC down, then Ctrl-C),
/// but the deploy WAS mined at nonce 0. The sweep must ride out a long outage (longer than a few retries),
/// move on to nonce 1, and the run must still say the record is stored and print the sheet with its
/// address and record id.
#[tokio::test(flavor = "multi_thread")]
async fn binary_reports_a_deploy_mined_after_giving_up() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    let rec = record(14);
    let (bin, sender, down, _) = deploy_mined_during_outage(&anvil, &rec, "late-deploy").await;
    bin.interrupt(); // gives up on the deploy while the RPC is down
    tokio::time::sleep(Duration::from_secs(12)).await;
    down.store(false, SeqCst);
    let (ok, out) = bin.finish();

    let p = ProviderBuilder::new().connect(&anvil.1).await.unwrap();
    assert_eq!(stored(&p, sender.create(0)).await, rec);
    assert!(!ok && out.contains("mined anyway"), "{out}");
    assert!(out.contains("out: Record stored."), "{out}");
    assert!(
        out.contains(&format!("out:   address:   {}", sender.create(0))),
        "{out}"
    );
    assert!(
        out.contains(&format!("out:   record id: {}", record_id(&rec))),
        "{out}"
    );
    assert_eq!(
        p.get_transaction_count(sender).await.unwrap(),
        2,
        "deploy at nonce 0, sweep at nonce 1"
    );
    assert!(p.get_balance(REFUND).await.unwrap() > U256::ZERO, "{out}");
    assert!(printed_key(&out).is_none(), "{out}");
}

/// The RPC goes down while the deploy confirms and comes back after it was mined: the run must keep
/// polling (not give up and let the sweep replace the deploy) and finish normally.
#[tokio::test(flavor = "multi_thread")]
async fn binary_rpc_outage_while_deploy_confirms_is_retried() {
    let Some(anvil) = start_anvil().await else {
        return;
    };
    let rec = record(15);
    let (bin, sender, down, dropped) =
        deploy_mined_during_outage(&anvil, &rec, "outage-deploy").await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    down.store(false, SeqCst);
    let (ok, out) = bin.finish();

    assert!(ok, "{out}");
    assert!(dropped.load(SeqCst) >= 1, "the outage must have been hit");
    let p = ProviderBuilder::new().connect(&anvil.1).await.unwrap();
    assert_eq!(stored(&p, sender.create(0)).await, rec);
    assert!(
        out.contains(&format!("out:   address:   {}", sender.create(0))),
        "{out}"
    );
}

/// The read-back goes to another chain state (`b` never saw the record), so the run fails AFTER the
/// deploy: the recovery-sheet block must already be on stdout (headed as mined, not yet as verified),
/// and the funds that arrived must still be swept.
#[tokio::test(flavor = "multi_thread")]
async fn binary_prints_sheet_even_when_read_back_fails() {
    let (Some(a), Some(b)) = (start_anvil().await, start_anvil().await) else {
        return;
    };
    let rec = record(13);
    let file = record_file(&rec, "sheet");
    let mut bin = Bin::spawn(&["--verify-rpc", &b.1, &a.1, &file, &REFUND.to_string()]);
    let (sender, wei) = bin.funding_request();
    send_eth(&a.1, sender, wei).await;
    let (ok, out) = bin.finish();
    assert!(
        !ok && out.contains("read-back") && out.contains("swept"),
        "{out}"
    );
    assert!(
        !out.contains("Do not send"),
        "funds arrived, so this is not a pre-funding exit: {out}"
    );
    assert!(
        out.contains("out: Deploy mined (tx 0x") && !out.contains("Record stored"),
        "{out}"
    );
    let p = ProviderBuilder::new().connect(&a.1).await.unwrap();
    assert!(
        p.get_balance(REFUND).await.unwrap() > U256::ZERO,
        "leftover must reach the refund address"
    );
    assert!(
        out.contains(&format!("out:   address:   {}", sender.create(0))),
        "{out}"
    );
    assert!(
        out.contains(&format!("out:   record id: {}", record_id(&rec))),
        "{out}"
    );
    assert!(printed_key(&out).is_none(), "{out}");
}

#[test]
fn binary_answers_help_and_version() {
    let (ok, out) = Bin::spawn(&["--help"]).finish();
    assert!(ok && out.contains("usage: publish"), "{out}");
    let (ok, out) = Bin::spawn(&["--version"]).finish();
    assert!(
        ok && out.contains(concat!("publish ", env!("CARGO_PKG_VERSION"))),
        "{out}"
    );
}

#[test]
fn binary_rejects_extra_positional_arguments() {
    let (ok, out) = Bin::spawn(&[
        "http://127.0.0.1:1",
        "rec.hex",
        "0x00000000000000000000000000000000000dead1",
        "extra",
    ])
    .finish();
    assert!(!ok && out.contains("unexpected extra argument"), "{out}");
}
