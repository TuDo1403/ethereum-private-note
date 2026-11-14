//! Publish a 147-byte record as the runtime code of a new contract ("code as data"), paying gas from a
//! throwaway key that exists only in memory. Flow: check chain -> wait for the throwaway address to be
//! funded -> deploy (the record becomes the code at `sender.create(0)`) -> read the code back -> sweep leftovers.
use alloy::{
    network::{Ethereum, TransactionBuilder},
    primitives::{Address, U256},
    providers::{PendingTransactionBuilder, Provider, ProviderBuilder},
    rpc::types::{TransactionReceipt, TransactionRequest},
    signers::local::PrivateKeySigner,
};
use std::time::{Duration, Instant};

/// Record format v1 size (see SPEC.md).
pub const RECORD_LEN: usize = 147;

const SWEEP_GAS: u64 = 21_000;
/// Gas limits are the node's estimate plus 20 %.
const GAS_MARGIN_PCT: u64 = 120;
/// The funding request is (all gas limits + sweep) x max fee x this. The x2 covers fee moves while we
/// wait for funds AND costs the gas estimate does not include (OP-stack L2s add an L1 data fee).
/// Everything unspent is swept back, so overshooting only locks funds for a few minutes.
const HEADROOM: u64 = 2;
/// Refuse to run when the quoted max fee or the total request exceeds these (a lying or broken RPC
/// could otherwise make us ask for, and then burn, a lot). Override with `Options::allow_high_fees`.
const MAX_FEE_CAP: u128 = 500_000_000_000; // 500 gwei
const MAX_TOTAL_CAP: u128 = 500_000_000_000_000_000; // 0.5 ETH
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(180);
const READBACK_TRIES: u32 = 5;
const READBACK_DELAY: Duration = Duration::from_secs(1);

/// Parse an address: `0x` required; mixed-case input must have a valid EIP-55 checksum.
pub fn parse_address(text: &str) -> Result<Address, String> {
    let body = text.strip_prefix("0x").ok_or("address must start with 0x")?;
    let mixed = body.chars().any(|c| c.is_ascii_lowercase()) && body.chars().any(|c| c.is_ascii_uppercase());
    let parsed = if mixed { Address::parse_checksummed(text, None).map_err(|e| e.to_string()) } else { text.parse::<Address>().map_err(|e| e.to_string()) };
    parsed.map_err(|e| format!("bad address: {e}"))
}

/// Parse a `record.hex` file: `0x` + 294 hex digits (surrounding whitespace allowed).
pub fn parse_record(text: &str) -> Result<Vec<u8>, String> {
    let body = text.trim().strip_prefix("0x").ok_or("record must start with 0x")?;
    let bytes = alloy::hex::decode(body).map_err(|e| format!("record is not hex: {e}"))?;
    if bytes.len() != RECORD_LEN {
        return Err(format!("record is {} bytes, expected {RECORD_LEN}", bytes.len()));
    }
    Ok(bytes)
}

/// Creation code whose runtime code is `0x00 || record`:
///   PUSH2 len; DUP1; PUSH1 10; RETURNDATASIZE (0); CODECOPY; RETURNDATASIZE (0); RETURN; then the data.
/// The 10-byte prefix is why the copy starts at offset 10. The leading 0x00 (STOP) keeps the data from ever
/// executing and, more importantly, keeps the code from starting with 0xEF, which EIP-3541 rejects: without
/// it about 1 in 256 random records would fail to deploy.
fn deploy_code(record: &[u8]) -> Vec<u8> {
    let len = u16::try_from(record.len() + 1).expect("record is far below the 24576-byte code limit");
    [&[0x61][..], &len.to_be_bytes(), &[0x80, 0x60, 0x0a, 0x3d, 0x39, 0x3d, 0xf3, 0x00], record].concat()
}

/// What the run produced; everything the recovery sheet needs.
#[derive(Debug)]
pub struct Outcome {
    pub chain_id: u64,
    /// Where the record lives: its code is `0x00 || record`. Derived from the sender, which is not needed again.
    pub address: Address,
    pub sender: Address,
    /// Wei returned to the refund address (0 if nothing was left to sweep).
    pub swept: U256,
}

pub struct Options<'a> {
    pub rpc_url: &'a str,
    /// Second RPC used ONLY for the read-back, so one lying node cannot fake "stored".
    pub verify_rpc_url: Option<&'a str>,
    pub refund: Address,
    pub fund_timeout: Duration,
    /// Confirmations to wait for on deploy and store (1 = included in a block).
    pub confirmations: u64,
    pub allow_high_fees: bool,
}

/// Shown to the user (possibly more than once: the amount is re-quoted after funding arrives).
pub struct FundRequest {
    pub sender: Address,
    pub chain_id: u64,
    pub required_wei: U256,
    pub refund: Address,
}

impl FundRequest {
    /// EIP-681 payment URI; `@chain_id` stops a wallet from paying on the wrong network.
    pub fn uri(&self) -> String {
        format!("ethereum:{}@{}?value={}", self.sender, self.chain_id, self.required_wei)
    }
}

fn e<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> String {
    move |err| format!("{what}: {err}")
}

/// RPC URLs may carry an API key and library errors echo them: hide them from every message.
fn scrub(mut msg: String, urls: &[&str]) -> String {
    for u in urls.iter().filter(|u| !u.is_empty()) {
        msg = msg.replace(u, "<rpc>").replace(u.trim_end_matches('/'), "<rpc>");
    }
    msg
}

/// Run the whole flow. `on_fund` is called before polling and again if the price moves.
pub async fn publish(opts: &Options<'_>, record: &[u8], mut on_fund: impl FnMut(&FundRequest)) -> Result<Outcome, String> {
    let urls = [opts.rpc_url, opts.verify_rpc_url.unwrap_or("")];
    run(opts, record, &mut on_fund).await.map_err(|m| scrub(m, &urls))
}

async fn run(opts: &Options<'_>, record: &[u8], on_fund: &mut dyn FnMut(&FundRequest)) -> Result<Outcome, String> {
    if record.len() != RECORD_LEN {
        return Err(format!("record is {} bytes, expected {RECORD_LEN}", record.len()));
    }

    // The signer (and every clone the provider holds) is dropped when this function returns;
    // k256's SigningKey zeroizes itself on drop. Nothing here ever prints or stores the key.
    let signer = PrivateKeySigner::random();
    let sender = signer.address();
    let provider = ProviderBuilder::new().wallet(signer).connect(opts.rpc_url).await.map_err(e("cannot connect to RPC"))?;
    let reader = ProviderBuilder::new().connect(opts.verify_rpc_url.unwrap_or(opts.rpc_url)).await.map_err(e("cannot connect to verify RPC"))?;

    let chain_id = provider.get_chain_id().await.map_err(e("chain id"))?;
    if chain_id == 0 {
        return Err("RPC reported chain id 0".into());
    }
    if reader.get_chain_id().await.map_err(e("verify RPC chain id"))? != chain_id {
        return Err("verify RPC is on a different chain".into());
    }
    eprintln!("chain id {chain_id}");

    // A sweep to an address with code runs that code and can exceed the fixed 21000 gas: refuse early.
    let refund = opts.refund;
    if [Address::ZERO, sender].contains(&refund) {
        return Err("refund address must be your own plain account, not zero or the sender".into());
    }
    if !provider.get_code_at(refund).await.map_err(e("get code"))?.is_empty() {
        return Err("refund address has code (contract or delegated account); the sweep could fail, use a plain account".into());
    }

    // The estimate is made once (an unfunded `from` is fine: no gas price is set on the request).
    let deploy_tx = TransactionRequest::default().with_deploy_code(deploy_code(record));
    let deploy_gas = provider.estimate_gas(deploy_tx.clone().with_from(sender)).await.map_err(e("deploy gas estimate"))?;
    let deploy_gas = deploy_gas.saturating_mul(GAS_MARGIN_PCT) / 100;
    let gas_total = deploy_gas + SWEEP_GAS;

    // From the moment funds can arrive, EVERY exit must go through the sweep below.
    let work = async {
        let (first_fee, _) = quote_fees(&provider).await?;
        let mut required = budget(gas_total, first_fee, opts.allow_high_fees)?;
        let mut req = FundRequest { sender, chain_id, required_wei: required, refund };
        on_fund(&req);
        let deadline = Instant::now() + opts.fund_timeout;
        let (max_fee, tip) = loop {
            let balance = provider.get_balance(sender).await.map_err(e("balance"))?;
            if balance >= required {
                // Funding may have taken minutes: re-quote and require the new total.
                let (max_fee, tip) = quote_fees(&provider).await?;
                let fresh = budget(gas_total, max_fee, opts.allow_high_fees)?;
                if balance >= fresh {
                    eprintln!("funded: {balance} wei");
                    break (max_fee, tip);
                }
                required = fresh;
                req.required_wei = fresh;
                on_fund(&req);
            } else if Instant::now() >= deadline {
                return Err(format!("timed out: {sender} holds {balance} wei, needs {required}"));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        };

        // The sender is brand new, so this is nonce 0, but the address is derived from whatever nonce is used.
        let nonce = next_nonce(&provider, sender).await?;
        let address = sender.create(nonce);
        let tx = deploy_tx.with_gas_limit(deploy_gas).with_max_fee_per_gas(max_fee).with_max_priority_fee_per_gas(tip).with_nonce(nonce);
        let pending = provider.send_transaction(tx).await.map_err(e("send deploy"))?;
        let receipt = confirmed(pending, "deploy", sender, opts.confirmations).await?;
        if receipt.contract_address != Some(address) {
            return Err(format!("deploy tx created {:?}, expected {address}", receipt.contract_address));
        }
        read_back(&reader, address, record).await?;
        eprintln!("stored and verified at {address} (tx {})", receipt.transaction_hash);
        Ok(address)
    }
    .await;

    let swept = sweep(&provider, sender, refund).await;
    match (work, swept) {
        (Ok(address), Ok(swept)) => Ok(Outcome { chain_id, address, sender, swept }),
        (Ok(_), Err(s)) => Err(format!("record is stored, but the sweep failed: {s}. Leftover ETH is stranded at {sender}")),
        (Err(w), Ok(v)) if v.is_zero() => Err(format!("{w} (nothing to sweep)")),
        (Err(w), Ok(v)) => Err(format!("{w} (swept {v} wei back to {refund})")),
        (Err(w), Err(s)) => Err(format!("{w}; ALSO the sweep failed: {s}. Funds may be stranded at {sender}")),
    }
}

/// EIP-1559 fees from the node; zero or absurd values are refused later by `budget`.
async fn quote_fees(p: &impl Provider) -> Result<(u128, u128), String> {
    let f = p.estimate_eip1559_fees().await.map_err(e("fee estimate (legacy non-EIP-1559 chains are unsupported)"))?;
    if f.max_fee_per_gas == 0 {
        return Err("RPC returned a zero max fee".into());
    }
    Ok((f.max_fee_per_gas, f.max_priority_fee_per_gas))
}

/// Total wei to request, with the headroom and the sanity caps applied.
fn budget(gas_total: u64, max_fee: u128, allow_high: bool) -> Result<U256, String> {
    let total = U256::from(gas_total) * U256::from(max_fee) * U256::from(HEADROOM);
    if !allow_high && (max_fee > MAX_FEE_CAP || total > U256::from(MAX_TOTAL_CAP)) {
        return Err(format!("quoted max fee {max_fee} wei/gas, total {total} wei: above the sanity cap (allow_high_fees overrides)"));
    }
    Ok(total)
}

/// Pending nonce, fetched fresh for every tx: alloy's cached nonce manager would skip a nonce after a
/// failed send and strand every later tx (including the sweep).
async fn next_nonce(p: &impl Provider, who: Address) -> Result<u64, String> {
    p.get_transaction_count(who).pending().await.map_err(e("nonce"))
}

/// Wait for inclusion (+ confirmations) with a timeout; errors name the sender and tx hash.
async fn confirmed(pending: PendingTransactionBuilder<Ethereum>, what: &str, sender: Address, confirmations: u64) -> Result<TransactionReceipt, String> {
    let hash = *pending.tx_hash();
    let receipt = pending
        .with_required_confirmations(confirmations.max(1))
        .with_timeout(Some(RECEIPT_TIMEOUT))
        .get_receipt()
        .await
        .map_err(|err| format!("{what} tx {hash} from {sender} not confirmed: {err}"))?;
    if !receipt.status() {
        return Err(format!("{what} tx {hash} reverted"));
    }
    Ok(receipt)
}

/// Read the code at `address` and require it to be `0x00 || record`. An empty answer is retried (a
/// load-balanced node can lag the receipt); a different non-empty answer fails at once.
async fn read_back(reader: &impl Provider, address: Address, record: &[u8]) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 0..READBACK_TRIES {
        if attempt > 0 {
            tokio::time::sleep(READBACK_DELAY).await;
        }
        match reader.get_code_at(address).await {
            Ok(c) if c.first() == Some(&0) && c[1..] == *record => return Ok(()),
            Ok(c) if !c.is_empty() => return Err("code read back from chain differs from the record sent".into()),
            Ok(_) => last = "empty".into(),
            Err(err) => last = err.to_string(),
        }
    }
    Err(format!("read-back of the code at {address} failed after {READBACK_TRIES} tries: {last}"))
}

/// Send everything above the fee to `refund`; returns the wei sent (0 = nothing worth sending).
/// If the node rejects the value for insufficient funds (e.g. an L2 data fee on top of gas), retry
/// with a doubled fee reserve.
async fn sweep(p: &impl Provider, sender: Address, refund: Address) -> Result<U256, String> {
    let balance = p.get_balance(sender).await.map_err(e("balance"))?;
    let (max_fee, tip) = quote_fees(p).await?;
    let mut reserve = U256::from(SWEEP_GAS) * U256::from(max_fee);
    let mut last = String::new();
    for _ in 0..4 {
        if balance <= reserve {
            return Ok(U256::ZERO);
        }
        let value = balance - reserve;
        let tx = TransactionRequest::default()
            .with_to(refund)
            .with_value(value)
            .with_gas_limit(SWEEP_GAS)
            .with_max_fee_per_gas(max_fee)
            .with_max_priority_fee_per_gas(tip)
            .with_nonce(next_nonce(p, sender).await?);
        match p.send_transaction(tx).await {
            Ok(pending) => {
                confirmed(pending, "sweep", sender, 1).await?;
                eprintln!("swept {value} wei to {refund}");
                return Ok(value);
            }
            Err(err) => {
                last = err.to_string();
                reserve *= U256::from(2);
            }
        }
    }
    Err(format!("send sweep: {last}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn deploy_code_layout() {
        let rec = [0xefu8; RECORD_LEN]; // starts with 0xEF on purpose: the 0x00 prefix must protect it
        let code = deploy_code(&rec);
        assert_eq!(&code[..3], &[0x61, 0x00, 0x94]); // PUSH2 148 = 1 + 147
        assert_eq!(code[10], 0x00); // the copy offset 0x0a lands exactly on the STOP byte
        assert_eq!(&code[11..], &rec);
    }

    #[test]
    fn address_parsing() {
        let lower = "0x52908400098527886e0f7030069857d2e4169ee7";
        let upper = "0x52908400098527886E0F7030069857D2E4169EE7"; // all-caps EIP-55 vector
        assert!(parse_address(lower).is_ok() && parse_address(upper).is_ok());
        assert!(parse_address("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB").is_ok()); // valid mixed
        assert!(parse_address("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6Fb").is_err()); // bad checksum
        assert!(parse_address(&lower[2..]).is_err()); // no 0x
    }

    #[test]
    fn uri_has_chain_id() {
        let r = FundRequest { sender: address!("00000000000000000000000000000000000000aa"), chain_id: 4153, required_wei: U256::from(7), refund: Address::ZERO };
        assert_eq!(r.uri(), "ethereum:0x00000000000000000000000000000000000000AA@4153?value=7");
    }

    #[test]
    fn scrub_hides_urls() {
        let m = scrub("error sending request for url (https://rpc.x/key/SECRET)".into(), &["https://rpc.x/key/SECRET", ""]);
        assert!(!m.contains("SECRET"));
    }

    #[test]
    fn budget_caps() {
        assert!(budget(1_000_000, 1_000_000_000, false).is_ok());
        assert!(budget(1_000_000, MAX_FEE_CAP + 1, false).is_err());
        assert!(budget(1_000_000, MAX_FEE_CAP + 1, true).is_ok());
    }

    #[test]
    fn record_parsing() {
        let ok = format!("0x{}\n", "ab".repeat(RECORD_LEN));
        assert_eq!(parse_record(&ok).unwrap().len(), RECORD_LEN);
        assert!(parse_record(&"ab".repeat(RECORD_LEN)).is_err()); // no 0x
        assert!(parse_record(&format!("0x{}", "ab".repeat(RECORD_LEN - 1))).is_err());
        assert!(parse_record(&format!("0x{}zz", "ab".repeat(RECORD_LEN - 1))).is_err());
    }
}
