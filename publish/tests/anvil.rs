//! End-to-end against a local anvil. Skipped (with a message) when `anvil` is not installed.
use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256, address},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use epn_publish::{FundRequest, Options, RECORD_LEN, publish as run};
use std::sync::{Arc, Mutex};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

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
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let child = match Command::new("anvil").args(["--silent", "--port", &port.to_string()]).args(extra).stdout(Stdio::null()).spawn() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("anvil not installed: skipping");
            return None;
        }
    };
    let url = format!("http://127.0.0.1:{port}");
    let anvil = Anvil(child, url.clone());
    let p = ProviderBuilder::new().connect(&url).await.unwrap();
    for _ in 0..50 {
        if p.get_chain_id().await.is_ok() {
            return Some(anvil);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("anvil did not start");
}

async fn set_code(url: &str, who: Address, code: &str) {
    let p = ProviderBuilder::new().connect(url).await.unwrap();
    p.raw_request::<_, ()>("anvil_setCode".into(), (who, code)).await.unwrap();
}

fn opts<'a>(url: &'a str) -> Options<'a> {
    Options { rpc_url: url, verify_rpc_url: None, refund: REFUND, fund_timeout: Duration::from_secs(30), confirmations: 1, allow_high_fees: false }
}

async fn send_eth(url: &str, to: Address, wei: U256) {
    let signer: PrivateKeySigner = DEV_KEY.parse().unwrap();
    let p = ProviderBuilder::new().wallet(EthereumWallet::from(signer)).connect(url).await.unwrap();
    p.send_transaction(TransactionRequest::default().to(to).value(wei)).await.unwrap().get_receipt().await.unwrap();
}

/// Run the flow, funding the throwaway sender from the dev account whenever asked (`pct` of the ask).
async fn run_funded_opts(o: &Options<'_>, record: &[u8], pct: u64) -> Result<epn_publish::Outcome, String> {
    let url = o.rpc_url.to_string();
    run(o, record, move |r: &FundRequest| {
        let (url, to, wei) = (url.clone(), r.sender, r.required_wei * U256::from(pct) / U256::from(100));
        tokio::spawn(async move { send_eth(&url, to, wei).await });
    })
    .await
}

async fn run_funded(url: &str, record: &[u8]) -> Result<epn_publish::Outcome, String> {
    run_funded_opts(&opts(url), record, 100).await
}

/// Make the next block's base fee `wei` and mine it, so the node's fee quote jumps.
async fn spike_base_fee(url: &str, wei: u128) {
    let p = ProviderBuilder::new().connect(url).await.unwrap();
    p.raw_request::<_, ()>("anvil_setNextBlockBaseFeePerGas".into(), (U256::from(wei),)).await.unwrap();
    p.raw_request::<_, String>("evm_mine".into(), ()).await.unwrap();
}

fn record(seed: u8) -> Vec<u8> {
    (0..RECORD_LEN).map(|i| seed.wrapping_add(i as u8)).collect()
}

/// What a restore reads: the code at the address is `0x00 || record`.
async fn stored(p: &impl Provider, at: Address) -> Vec<u8> {
    let code = p.get_code_at(at).await.unwrap();
    assert_eq!(code.first(), Some(&0), "code must start with the STOP byte");
    code[1..].to_vec()
}

#[tokio::test(flavor = "multi_thread")]
async fn deploys_record_as_code_reads_back_and_sweeps() {
    let Some(anvil) = start_anvil().await else { return };
    let p = ProviderBuilder::new().connect(&anvil.1).await.unwrap();

    let rec = record(1);
    let out = run_funded(&anvil.1, &rec).await.unwrap();
    assert_eq!(out.address, out.sender.create(0));
    assert!(out.swept > U256::ZERO);
    assert_eq!(p.get_balance(REFUND).await.unwrap(), out.swept);
    // Sender is drained to (almost) nothing: only the sweep's fee headroom may remain.
    assert!(p.get_balance(out.sender).await.unwrap() < U256::from(10u64).pow(U256::from(16)));
    assert_eq!(stored(&p, out.address).await, rec);

    // Second run: new throwaway sender, new address; the first record is untouched.
    let rec2 = record(77);
    let out2 = run_funded(&anvil.1, &rec2).await.unwrap();
    assert_ne!(out.address, out2.address);
    assert_eq!(stored(&p, out2.address).await, rec2);
    assert_eq!(stored(&p, out.address).await, rec);
}

/// EIP-3541 rejects code that starts with 0xEF; the STOP prefix must make such a record deployable.
#[tokio::test(flavor = "multi_thread")]
async fn record_starting_with_0xef_deploys() {
    let Some(anvil) = start_anvil().await else { return };
    let mut rec = record(1);
    rec[0] = 0xef;
    let out = run_funded(&anvil.1, &rec).await.unwrap();
    let p = ProviderBuilder::new().connect(&anvil.1).await.unwrap();
    assert_eq!(stored(&p, out.address).await, rec);
}

#[tokio::test(flavor = "multi_thread")]
async fn refund_with_code_or_special_address_is_rejected_before_funding() {
    let Some(anvil) = start_anvil().await else { return };
    set_code(&anvil.1, REFUND, "0x6000").await;
    let asked = Arc::new(Mutex::new(0));
    let a2 = asked.clone();
    let err = run(&opts(&anvil.1), &record(1), move |_: &FundRequest| *a2.lock().unwrap() += 1).await.unwrap_err();
    assert!(err.contains("has code"), "{err}");
    let mut o = opts(&anvil.1);
    o.refund = Address::ZERO;
    assert!(run(&o, &record(1), |_: &FundRequest| {}).await.unwrap_err().contains("refund address must be"));
    assert_eq!(*asked.lock().unwrap(), 0, "must fail before asking for funds");
}

#[tokio::test(flavor = "multi_thread")]
async fn failure_after_funding_still_sweeps() {
    let (Some(a), Some(b)) = (start_anvil().await, start_anvil().await) else { return };
    // Read-back goes to a different chain state (b never saw the record): the flow fails AFTER deploying.
    let mut o = opts(&a.1);
    o.verify_rpc_url = Some(&b.1);
    let err = run_funded_opts(&o, &record(5), 100).await.unwrap_err();
    assert!(err.contains("read-back") && err.contains("swept"), "{err}");
    let p = ProviderBuilder::new().connect(&a.1).await.unwrap();
    assert!(p.get_balance(REFUND).await.unwrap() > U256::ZERO, "leftover must reach the refund address");
}

#[tokio::test(flavor = "multi_thread")]
async fn second_rpc_can_verify_and_confirmations_are_awaited() {
    let Some(a) = start_anvil_with(&["--block-time", "1"]).await else { return };
    let mut o = opts(&a.1);
    o.verify_rpc_url = Some(&a.1);
    o.confirmations = 2;
    run_funded_opts(&o, &record(9), 100).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn funding_timeout_sweeps_partial_funds() {
    let Some(anvil) = start_anvil().await else { return };
    let mut o = opts(&anvil.1);
    o.fund_timeout = Duration::from_secs(4);
    let err = run_funded_opts(&o, &record(1), 50).await.unwrap_err();
    assert!(err.contains("timed out") && err.contains("swept"), "{err}");
    let p = ProviderBuilder::new().connect(&anvil.1).await.unwrap();
    assert!(p.get_balance(REFUND).await.unwrap() > U256::ZERO);
}

#[tokio::test(flavor = "multi_thread")]
async fn fees_are_requoted_after_funding() {
    let Some(anvil) = start_anvil().await else { return };
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
    assert!(asks.len() >= 2 && asks[1] > asks[0], "expected a larger second ask, got {asks:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn absurd_fees_are_refused_before_funding() {
    let Some(anvil) = start_anvil().await else { return };
    spike_base_fee(&anvil.1, 5_000_000_000_000).await; // 5000 gwei
    let err = run(&opts(&anvil.1), &record(1), |_: &FundRequest| panic!("must not ask for funds")).await.unwrap_err();
    assert!(err.contains("sanity cap"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn rpc_url_secret_is_not_leaked_in_errors() {
    let o = Options { rpc_url: "http://127.0.0.1:1/?key=SECRETKEY", ..opts("") };
    let err = run(&o, &record(1), |_: &FundRequest| {}).await.unwrap_err();
    assert!(!err.contains("SECRETKEY"), "{err}");
}
