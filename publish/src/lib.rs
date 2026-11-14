//! Publish a record (see SPEC.md) as the runtime code of a new contract ("code as data"),
//! paying gas from a throwaway key that exists only in memory. Flow: check chain -> wait for the throwaway
//! address to be funded -> deploy (the record becomes the code at `sender.create(0)`) -> read the code back
//! -> sweep leftovers.
use alloy::{
    eips::BlockNumberOrTag,
    network::TransactionBuilder,
    primitives::{Address, B256, U256, utils::format_ether},
    providers::{Provider, ProviderBuilder},
    rpc::client::RpcClient,
    rpc::types::{TransactionReceipt, TransactionRequest},
    signers::local::PrivateKeySigner,
    transports::http::reqwest::{self, Url},
};
use epn_core::{record::parse_record as check_record, record_id};
use std::cell::Cell;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Write a line to stderr, ignoring failure. `eprintln!` panics when stderr is gone (terminal closed,
/// SIGHUP), and the run must still reach the sweep.
macro_rules! log {
    ($($t:tt)*) => {{ let _ = writeln!(std::io::stderr(), $($t)*); }};
}

const SWEEP_GAS: u64 = 21_000;
/// After a sweep, keep the key if what stayed behind exceeds this many times what the sweep actually paid.
/// A normal run leaves about one fee (the quote is ~2x the price paid); a retry with a doubled reserve about
/// three; only a quote far above the real price (a broken or lying RPC) goes past this.
const LEFTOVER_KEEP_RATIO: u64 = 4;
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
/// The tip is capped at max(base fee, this); see `fees_from`.
const TIP_CAP_FLOOR: u128 = 10_000_000; // 0.01 gwei
/// Deploy receipt timeout: this plus `PER_CONFIRMATION` for every confirmation asked for.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(180);
const PER_CONFIRMATION: Duration = Duration::from_secs(30);
const READBACK_TRIES: u32 = 5;
const READBACK_DELAY: Duration = Duration::from_secs(1);
const POLL: Duration = Duration::from_secs(2);
/// Upper bound on any single RPC request (connect + response).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const SWEEP_TRIES: u32 = 6;
/// How long one sweep tx may stay unmined before it is re-sent with a higher fee.
const SWEEP_WAIT: Duration = Duration::from_secs(90);

/// Parse an address: `0x` required; mixed-case input must have a valid EIP-55 checksum.
pub fn parse_address(text: &str) -> Result<Address, String> {
    let body = text
        .strip_prefix("0x")
        .ok_or("address must start with 0x")?;
    let mixed = body.chars().any(|c| c.is_ascii_lowercase())
        && body.chars().any(|c| c.is_ascii_uppercase());
    let parsed = if mixed {
        Address::parse_checksummed(text, None).map_err(|e| e.to_string())
    } else {
        text.parse::<Address>().map_err(|e| e.to_string())
    };
    parsed.map_err(|e| format!("bad address: {e}"))
}

/// Parse a `record.hex` file: `0x` + the record's hex digits (surrounding whitespace allowed). The record
/// must be well-formed before a single wei is spent: it is permanent, and one that `recover` refuses would
/// be useless forever. A record is at most 250 bytes (24 fixed header + 5 kinds + 5 x 32 masked shares + 12 nonce + 49 ciphertext), so its code (251 bytes with the 0x00
/// prefix) is far below the EIP-170 limit of 24576 bytes.
pub fn parse_record(text: &str) -> Result<Vec<u8>, String> {
    let body = text
        .trim()
        .strip_prefix("0x")
        .ok_or("record must start with 0x")?;
    let bytes = alloy::hex::decode(body).map_err(|e| format!("record is not hex: {e}"))?;
    check_record(&bytes)?;
    Ok(bytes)
}

/// "0.0012 ETH (1200000000000000 wei)".
pub fn amount(wei: U256) -> String {
    format!("{} ETH ({wei} wei)", format_ether(wei))
}

/// Creation code whose runtime code is `0x00 || record`:
///   PUSH2 len; DUP1; PUSH1 10; RETURNDATASIZE (0); CODECOPY; RETURNDATASIZE (0); RETURN; then the data.
/// The 10-byte prefix is why the copy starts at offset 10. The leading 0x00 (STOP) keeps the data from ever
/// executing and, more importantly, keeps the code from starting with 0xEF, which EIP-3541 rejects: without
/// it about 1 in 256 random records would fail to deploy.
fn deploy_code(record: &[u8]) -> Vec<u8> {
    let len = u16::try_from(record.len() + 1).expect("a valid record is at most 250 bytes");
    [
        &[0x61][..],
        &len.to_be_bytes(),
        &[0x80, 0x60, 0x0a, 0x3d, 0x39, 0x3d, 0xf3, 0x00],
        record,
    ]
    .concat()
}

/// True if `code` is exactly what the deploy of `record` leaves: `0x00 || record`, byte for byte.
fn holds_record(code: &[u8], record: &[u8]) -> bool {
    code.first() == Some(&0) && code[1..] == *record
}

/// Set by `catch_signals`' handler; consumed by `interrupted`.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn on_signal(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst); // an atomic store is async-signal-safe
}

/// Make Ctrl-C (SIGINT), SIGTERM and SIGHUP (terminal closed) set a flag instead of killing the process,
/// so a run that holds the only copy of the gas key stops and sweeps before it exits; a second signal
/// during the sweep abandons it (and prints the key). For the binary, called right before `publish`
/// (not before its prompts, where Ctrl-C should still just quit). Without it, these signals kill the
/// process as usual.
#[cfg(unix)]
#[allow(unsafe_code)] // the workspace denies unsafe; this one libc call has a SAFETY note below
pub fn catch_signals() {
    let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: the handler only does an atomic store, which is async-signal-safe.
        unsafe { libc::signal(sig, handler) };
    }
}

/// Resolves once a caught signal arrives (never, if `catch_signals` was not called).
async fn interrupted() {
    while !INTERRUPTED.swap(false, Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// What the run produced; everything the recovery sheet needs.
#[derive(Debug)]
pub struct Outcome {
    pub chain_id: u64,
    /// Where the record lives: its code is `0x00 || record`. Derived from the sender, which is not needed again.
    pub address: Address,
    pub sender: Address,
    pub record_id: String,
    /// Wei returned to the refund address (0 if nothing was left to sweep).
    pub swept: U256,
}

pub struct Options<'a> {
    pub rpc_url: &'a str,
    /// Second RPC used ONLY for the read-back, so one lying node cannot fake "stored".
    pub verify_rpc_url: Option<&'a str>,
    pub refund: Address,
    pub fund_timeout: Duration,
    /// Confirmations to wait for on the deploy (1 = included in a block).
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
        format!(
            "ethereum:{}@{}?value={}",
            self.sender, self.chain_id, self.required_wei
        )
    }
}

fn e<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> String {
    move |err| format!("{what}: {err}")
}

/// Every form in which an RPC URL (and an API key in it) can appear in a library error: as given, and
/// as reqwest prints it after parsing (lowercased scheme and host, default port dropped, `/` added).
fn secret_forms(urls: &[&str]) -> Vec<String> {
    let mut forms = Vec::new();
    for u in urls.iter().filter(|u| !u.is_empty()) {
        forms.push(u.to_string());
        if let Ok(parsed) = Url::parse(u) {
            forms.push(parsed.to_string());
        }
    }
    forms.extend(
        forms
            .clone()
            .iter()
            .map(|f| f.trim_end_matches('/').to_string()),
    );
    forms.retain(|f| !f.is_empty());
    // Longest first, so replacing a shorter form cannot leave the tail of a longer one behind.
    forms.sort_by_key(|f| std::cmp::Reverse(f.len()));
    forms
}

fn scrub(mut msg: String, secrets: &[String]) -> String {
    for s in secrets {
        msg = msg.replace(s.as_str(), "<rpc>");
    }
    msg
}

/// An HTTP RPC client whose every request gives up after `REQUEST_TIMEOUT`. Deadlines are only checked
/// between calls, so without this one stalled request (a server that accepts and never answers) would
/// hold the funding wait, the confirmation wait or the sweep forever.
fn http_client(url: &str) -> Result<RpcClient, String> {
    let url = Url::parse(url).map_err(e("bad RPC URL"))?;
    let http = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        // A 307/308 would re-send the signed transaction to whatever host the RPC names.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(e("HTTP client"))?;
    Ok(RpcClient::new_http_with_client(http, url))
}

/// Last resort for ETH the sweep could not return: if dropped while `armed`, prints the throwaway key on
/// stderr. Armed from the moment the funding address is shown until the funds have arrived AND the sweep
/// has finished; dropping also happens on a panic or when the future is cancelled. The key only ever
/// holds this run's gas money, and printing it is the only way the user can still recover that money.
struct Rescue {
    signer: PrivateKeySigner,
    chain_id: u64,
    armed: Cell<bool>,
}

impl Drop for Rescue {
    fn drop(&mut self) {
        if self.armed.get() {
            let (addr, id) = (self.signer.address(), self.chain_id);
            log!(
                "\n!!! This process is exiting and ETH may be at, or still on its way to, {addr} on chain {id}."
            );
            log!(
                "!!! Below is that throwaway address's private key: the ONLY way to recover that ETH. It holds only"
            );
            log!(
                "!!! this run's gas money, but anyone who sees it can take that money: import it into a wallet now"
            );
            log!(
                "!!! (or `cast send <your address> --value <balance minus fee> --private-key <key> --rpc-url <RPC>`)."
            );
            log!(
                "!!! THROWAWAY PRIVATE KEY: 0x{}",
                alloy::hex::encode(self.signer.to_bytes())
            );
        }
    }
}

/// Run the whole flow. `on_fund` is called before polling and again if the price moves.
pub async fn publish(
    opts: &Options<'_>,
    record: &[u8],
    mut on_fund: impl FnMut(&FundRequest),
) -> Result<Outcome, String> {
    let secrets = secret_forms(&[opts.rpc_url, opts.verify_rpc_url.unwrap_or("")]);
    run(opts, record, &mut on_fund, &secrets)
        .await
        .map_err(|m| scrub(m, &secrets))
}

async fn run(
    opts: &Options<'_>,
    record: &[u8],
    on_fund: &mut dyn FnMut(&FundRequest),
    secrets: &[String],
) -> Result<Outcome, String> {
    check_record(record)?;
    let id = record_id(record);
    log!(
        "record v{}, {} bytes, record id {id}",
        record[0],
        record.len()
    );

    // The signer (and every clone the provider holds) is dropped when this function returns; k256's
    // SigningKey zeroizes itself on drop. The key is printed only by `Rescue`, never stored.
    let signer = PrivateKeySigner::random();
    let sender = signer.address();
    let rescue_signer = signer.clone();
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_client(http_client(opts.rpc_url)?);
    let reader = ProviderBuilder::new()
        .connect_client(http_client(opts.verify_rpc_url.unwrap_or(opts.rpc_url))?);

    // Nothing is at stake before the funding address is shown, so Ctrl-C may simply abandon this: without
    // the race, a stalled RPC would hold the process (and its signal handler) for 20 s per call.
    let refund = opts.refund;
    let preflight = async {
        let chain_id = provider.get_chain_id().await.map_err(e("chain id"))?;
        if chain_id == 0 {
            return Err("RPC reported chain id 0".into());
        }
        if reader
            .get_chain_id()
            .await
            .map_err(e("verify RPC chain id"))?
            != chain_id
        {
            return Err("verify RPC is on a different chain".into());
        }
        log!("chain id {chain_id}");

        // The record's address is fixed by the sender and nonce 0. Only this process holds the key and the
        // deploy is the first tx it sends, so the only other tx that can ever take nonce 0 is our own sweep
        // replacing a stuck deploy; then nothing is stored at `address`, which the end of `run` re-checks.
        let address = sender.create(0);

        // A sweep to an address with code runs that code and can exceed the fixed 21000 gas: refuse early.
        if [Address::ZERO, sender].contains(&refund) {
            return Err(
                "refund address must be your own plain account, not zero or the sender".into(),
            );
        }
        if !provider
            .get_code_at(refund)
            .await
            .map_err(e("get code"))?
            .is_empty()
        {
            return Err("refund address has code (contract or delegated account); the sweep could fail, use a plain account".into());
        }

        // The estimate is made once (an unfunded `from` is fine: no gas price is set on the request).
        let deploy_tx = TransactionRequest::default().with_deploy_code(deploy_code(record));
        let deploy_gas = provider
            .estimate_gas(deploy_tx.clone().with_from(sender))
            .await
            .map_err(e("deploy gas estimate"))?;
        let deploy_gas = deploy_gas.saturating_mul(GAS_MARGIN_PCT) / 100;
        Ok::<_, String>((chain_id, address, deploy_tx, deploy_gas))
    };
    let (chain_id, address, deploy_tx, deploy_gas) = tokio::select! {
        r = preflight => r?,
        () = interrupted() => return Err("interrupted before anything was funded".into()),
    };
    let gas_total = deploy_gas + SWEEP_GAS;

    let rescue = Rescue {
        signer: rescue_signer,
        chain_id,
        armed: Cell::new(false),
    };
    // `funded`: the funding wait completed. `sent`: fees of the deploy tx once sent, which the sweep must
    // outbid to replace it if it is still pending. `sheet`: the recovery-sheet block was printed.
    let (funded, sent, sheet) = (
        Cell::new(false),
        Cell::new(None::<(u128, u128)>),
        Cell::new(false),
    );

    // From the moment funds can arrive, EVERY exit must go through the sweep below.
    let work = async {
        let (first_fee, _) = quote_fees(&provider).await?;
        let mut required = budget(gas_total, first_fee, opts.allow_high_fees)?;
        let mut req = FundRequest {
            sender,
            chain_id,
            required_wei: required,
            refund,
        };
        rescue.armed.set(true); // from here on, a payment may be on its way to `sender`
        on_fund(&req);
        let deadline = Instant::now() + opts.fund_timeout;
        // A failed RPC call must not end the run while a payment may be in flight: log it and retry
        // until the deadline.
        let (max_fee, tip) = loop {
            let late = Instant::now() >= deadline;
            match provider.get_balance(sender).await {
                Ok(balance) if balance >= required => match quote_fees(&provider).await {
                    // Funding may have taken minutes: re-quote and require the new total.
                    Ok((max_fee, tip)) => {
                        let fresh = budget(gas_total, max_fee, opts.allow_high_fees)?;
                        if balance >= fresh {
                            log!("funded: {}", amount(balance));
                            break (max_fee, tip);
                        }
                        required = fresh;
                        req.required_wei = fresh;
                        on_fund(&req);
                    }
                    Err(err) if late => return Err(format!("timed out waiting for funds: {err}")),
                    Err(err) => log!("fee quote failed, retrying: {}", scrub(err, secrets)),
                },
                Ok(balance) if late => {
                    return Err(format!(
                        "timed out: {sender} holds {}, needs {}",
                        amount(balance),
                        amount(required)
                    ));
                }
                Ok(_) => {}
                Err(err) if late => {
                    return Err(format!(
                        "timed out waiting for funds: balance check failed: {err}"
                    ));
                }
                Err(err) => log!(
                    "balance check failed, retrying: {}",
                    scrub(err.to_string(), secrets)
                ),
            }
            tokio::time::sleep(POLL).await;
        };
        funded.set(true);

        let tx = deploy_tx
            .with_gas_limit(deploy_gas)
            .with_max_fee_per_gas(max_fee)
            .with_max_priority_fee_per_gas(tip)
            .with_nonce(0);
        sent.set(Some((max_fee, tip))); // before sending: a send error may still have reached the pool
        let hash = *provider
            .send_transaction(tx)
            .await
            .map_err(e("send deploy"))?
            .tx_hash();
        log!("deploy tx {hash} sent");
        let receipt = confirmed(&provider, hash, "deploy", sender, opts.confirmations).await?;
        if receipt.contract_address != Some(address) {
            return Err(format!(
                "deploy tx created {:?}, expected {address}",
                receipt.contract_address
            ));
        }
        // Print the sheet now: the record is on chain whatever fails after this point.
        print_sheet(chain_id, address, &id, Some(receipt.transaction_hash));
        sheet.set(true);
        read_back(&reader, address, record).await?;
        log!("read back and verified");
        Ok(())
    };
    let work = tokio::select! {
        r = work => r,
        () = interrupted() => Err("interrupted (signal received)".to_string()),
    };

    // A signal that arrived just as the work finished is already handled by sweeping now; only a
    // new one may abandon the sweep.
    INTERRUPTED.store(false, Ordering::SeqCst);
    // Nothing can be at `sender` before its address was shown, so an earlier failure sweeps nothing.
    let swept = if rescue.armed.get() {
        tokio::select! {
            r = sweep(&provider, sender, refund, sent.get().unwrap_or((0, 0)), opts.allow_high_fees, secrets) => r,
            () = interrupted() => Err("interrupted again during the sweep".to_string()),
        }
    } else {
        Ok((U256::ZERO, false))
    };
    // Once the funds have arrived and the sweep has finished, nothing more is expected at `sender` and
    // the key may be forgotten. In every other case `rescue` prints it when this function returns.
    // A zero balance after funding is no proof of a finished sweep (a lagging or lying RPC can say so):
    // only a sweep that sent something lets the key go, and not one that left a recoverable amount.
    if funded.get() && swept.as_ref().is_ok_and(|(v, keep)| !v.is_zero() && !keep) {
        rescue.armed.set(false);
    }
    let swept = swept.map(|(v, _)| v);

    // A deploy that was sent but not confirmed (timeout, Ctrl-C, RPC error) may still have been mined,
    // e.g. while the sweep was being prepared (the sweep then moved on to nonce 1). Then the record IS
    // stored and the user needs the sheet. One check on the verify RPC, byte for byte.
    let mut late_note = String::new();
    if work.is_err()
        && sent.get().is_some()
        && !sheet.get()
        && reader
            .get_code_at(address)
            .await
            .is_ok_and(|c| holds_record(&c, record))
    {
        print_sheet(chain_id, address, &id, None);
        late_note = format!(
            " The deploy was mined anyway: the record IS stored at {address} (sheet printed above)."
        );
    }

    // Exit before the funds arrived, after the address was shown: a payment may still be on its way.
    let dont_send = if !funded.get() && rescue.armed.get() {
        format!(
            " Do not send funds to {sender}: this run is over. If you already sent some, the THROWAWAY PRIVATE KEY printed above is the only way to recover them."
        )
    } else {
        String::new()
    };
    let stranded = format!(
        "Any ETH at {sender} is stuck there: the THROWAWAY PRIVATE KEY printed above is the only way to recover it."
    );
    let swept_note = |v: U256| {
        if v.is_zero() {
            " (nothing to sweep)".to_string()
        } else {
            format!(" (swept {} back to {refund})", amount(v))
        }
    };
    match (work, swept) {
        (Ok(()), Ok(swept)) => Ok(Outcome {
            chain_id,
            address,
            sender,
            record_id: id,
            swept,
        }),
        (Ok(()), Err(s)) => Err(format!(
            "record is stored, but the sweep failed: {s}. {stranded}"
        )),
        (Err(w), Ok(v)) => Err(format!("{w}{}.{late_note}{dont_send}", swept_note(v))),
        (Err(w), Err(s)) => Err(format!(
            "{w}; ALSO the sweep failed: {s}. {stranded}{late_note}{dont_send}"
        )),
    }
}

/// The chain id / address / record id block for the recovery sheet, on stdout.
fn print_sheet(chain_id: u64, address: Address, id: &str, tx: Option<B256>) {
    let mut out = std::io::stdout().lock();
    let via = tx.map(|t| format!(" (tx {t})")).unwrap_or_default();
    let _ = writeln!(
        out,
        "\nRecord stored{via}. Put these on the recovery sheet:"
    );
    let _ = writeln!(out, "  chain id:  {chain_id}");
    let _ = writeln!(out, "  address:   {address}");
    let _ = writeln!(out, "  record id: {id}");
    let _ = writeln!(
        out,
        "  read:      cast code {address} --rpc-url <RPC>   (the code is 0x00 followed by the record)"
    );
}

/// EIP-1559 fees from the latest base fee and the node's suggested tip.
async fn quote_fees(p: &impl Provider) -> Result<(u128, u128), String> {
    let block = p
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await
        .map_err(e("latest block"))?
        .ok_or("RPC returned no latest block")?;
    let base = block
        .header
        .base_fee_per_gas
        .ok_or("latest block has no base fee (legacy non-EIP-1559 chains are unsupported)")?;
    let tip = p
        .get_max_priority_fee_per_gas()
        .await
        .map_err(e("priority fee"))?;
    let (max_fee, tip) = fees_from(base.into(), tip);
    if max_fee == 0 {
        return Err("RPC returned a zero base fee and tip".into());
    }
    Ok((max_fee, tip))
}

/// (max fee, tip) = (2 x base + tip, tip): the usual rule, which survives several full blocks. Unlike
/// unused max fee, the tip is really paid, and nodes often suggest a flat 1 gwei: on an L2 with a
/// ~0.001 gwei base fee that overpays ~1000x. So the tip is capped at the base fee, but never below
/// 0.01 gwei so a sequencer's minimum tip is still met (worst case ~150k gas x 0.01 gwei, negligible).
fn fees_from(base: u128, suggested_tip: u128) -> (u128, u128) {
    let tip = suggested_tip.min(base.max(TIP_CAP_FLOOR));
    (base.saturating_mul(2).saturating_add(tip), tip)
}

/// Total wei to request, with the headroom and the sanity caps applied.
fn budget(gas_total: u64, max_fee: u128, allow_high: bool) -> Result<U256, String> {
    let total = U256::from(gas_total) * U256::from(max_fee) * U256::from(HEADROOM);
    if !allow_high && (max_fee > MAX_FEE_CAP || total > U256::from(MAX_TOTAL_CAP)) {
        return Err(format!(
            "quoted max fee {max_fee} wei/gas, total {}: above the sanity cap (allow_high_fees overrides)",
            amount(total)
        ));
    }
    Ok(total)
}

/// Wait until `hash` is mined with `confirmations` (1 = included), within a timeout that grows with the
/// confirmations asked for. RPC errors are retried, not fatal: one failed call must not make the run give
/// up on a deploy that is being mined (the sweep would then try to replace it). The receipt is re-read on
/// every poll, so a reorg that drops the tx is noticed. Errors name the sender and tx hash.
async fn confirmed(
    p: &impl Provider,
    hash: B256,
    what: &str,
    sender: Address,
    confirmations: u64,
) -> Result<TransactionReceipt, String> {
    let confirmations = confirmations.max(1);
    let deadline = Instant::now()
        + RECEIPT_TIMEOUT
        + PER_CONFIRMATION.saturating_mul(u32::try_from(confirmations).unwrap_or(u32::MAX));
    let mut last = "not mined yet".to_string();
    while Instant::now() < deadline {
        match p.get_transaction_receipt(hash).await {
            Ok(Some(r)) if !r.status() => return Err(format!("{what} tx {hash} reverted")),
            Ok(Some(r)) => match (r.block_number, p.get_block_number().await) {
                (Some(mined), Ok(head))
                    if head.saturating_add(1) >= mined.saturating_add(confirmations) =>
                {
                    return Ok(r);
                }
                (_, Err(err)) => last = err.to_string(),
                _ => last = "waiting for confirmations".into(),
            },
            Ok(None) => {}
            Err(err) => last = err.to_string(),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(format!(
        "{what} tx {hash} from {sender} not confirmed in time: {last}"
    ))
}

/// Read the code at `address` and require it to be `0x00 || record`, byte for byte. An empty answer is
/// retried (a load-balanced node can lag the receipt); a different non-empty answer fails at once.
async fn read_back(reader: &impl Provider, address: Address, record: &[u8]) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 0..READBACK_TRIES {
        if attempt > 0 {
            tokio::time::sleep(READBACK_DELAY).await;
        }
        match reader.get_code_at(address).await {
            Ok(c) if holds_record(&c, record) => return Ok(()),
            Ok(c) if !c.is_empty() => {
                return Err("code read back from chain differs from the record sent".into());
            }
            Ok(_) => last = "empty".into(),
            Err(err) => last = err.to_string(),
        }
    }
    Err(format!(
        "read-back of the code at {address} failed after {READBACK_TRIES} tries: {last}"
    ))
}

/// Both fee fields raised by 12.5 %, rounded up: a replacement must outbid the pending tx on both
/// (geth and most pools require +10 %).
fn bump((max_fee, tip): (u128, u128)) -> (u128, u128) {
    (
        max_fee.saturating_add(max_fee.div_ceil(8)),
        // At least +1: a tip of 0 must still rise, or a pool refuses the replacement of a tip-0 deploy.
        tip.saturating_add(tip.div_ceil(8).max(1)),
    )
}

/// Send everything above the sweep's own fee to `refund`; returns the wei sent (0 only when `sender` is
/// empty) and whether the key must still be kept because a recoverable amount stayed behind. A non-zero
/// balance that cannot be swept is an error, so the caller keeps (prints) the key.
///
/// The sweep must work even when the deploy is stuck in the mempool. So it uses the latest MINED nonce and
/// balance (not the pending nonce, which would queue it behind the stuck deploy while its value counts on
/// money the deploy may still spend) and fees at least 12.5 % above `sent` (the deploy's fees), which
/// replaces the stuck deploy. The value is the mined balance minus the sweep's max cost, so the sweep pays
/// for itself. Every failure re-reads the state and tries again: "nonce too low" or another tx mined at our
/// nonce (the deploy won after all), an underpriced replacement or a sweep that stays unmined (fee raised
/// another 12.5 %), insufficient funds (an L2 data fee on top of gas: reserve doubled).
async fn sweep(
    p: &impl Provider,
    sender: Address,
    refund: Address,
    sent: (u128, u128),
    allow_high: bool,
    secrets: &[String],
) -> Result<(U256, bool), String> {
    let mut floor = bump(sent);
    let mut reserve_mul = 1u64;
    let mut last = String::new();
    for attempt in 0..SWEEP_TRIES {
        if attempt > 0 {
            log!(
                "sweep attempt {attempt} failed, retrying: {}",
                scrub(last.clone(), secrets)
            );
            tokio::time::sleep(POLL).await;
        }
        let state = async {
            let nonce = p
                .get_transaction_count(sender)
                .latest()
                .await
                .map_err(e("nonce"))?;
            let balance = p.get_balance(sender).latest().await.map_err(e("balance"))?;
            Ok::<_, String>((nonce, balance, quote_fees(p).await?))
        };
        let (nonce, balance, (quoted_fee, quoted_tip)) = match state.await {
            Ok(s) => s,
            Err(err) => {
                last = err;
                continue;
            }
        };
        // The same sanity cap as the funding request: an inflated quote must not size a reserve that eats
        // the balance (it would be left at `sender`, whose key is then forgotten). Never below `floor`,
        // which must outbid a stuck deploy; a capped fee too low for the chain just fails to mine and is
        // retried, ending in an error that keeps the key.
        let quoted_fee = if allow_high {
            quoted_fee
        } else {
            quoted_fee.min(MAX_FEE_CAP)
        };
        let max_fee = quoted_fee.max(floor.0);
        let tip = quoted_tip.max(floor.1).min(max_fee);
        let reserve = U256::from(SWEEP_GAS) * U256::from(max_fee) * U256::from(reserve_mul);
        if balance.is_zero() {
            log!("nothing to sweep: {sender} is empty");
            return Ok((U256::ZERO, false));
        }
        if balance <= reserve {
            // Not Ok(0): that would let the caller forget the only key to this balance.
            last = format!(
                "{} at {sender} does not cover the sweep's fee at {max_fee} wei/gas",
                amount(balance)
            );
            continue;
        }
        let value = balance - reserve;
        let tx = TransactionRequest::default()
            .with_to(refund)
            .with_value(value)
            .with_gas_limit(SWEEP_GAS)
            .with_max_fee_per_gas(max_fee)
            .with_max_priority_fee_per_gas(tip)
            .with_nonce(nonce);
        let hash = match p.send_transaction(tx).await {
            Ok(pending) => *pending.tx_hash(),
            Err(err) => {
                last = format!("send sweep: {err}");
                let lower = last.to_lowercase();
                if lower.contains("insufficient funds") {
                    reserve_mul *= 2;
                } else if lower.contains("underpriced") || lower.contains("fee too low") {
                    floor = bump((max_fee, tip));
                }
                continue;
            }
        };
        log!(
            "sweep tx {hash} sent: {} to {refund}, nonce {nonce}, max fee {max_fee} wei/gas",
            amount(value)
        );
        match mined(p, hash, sender, nonce).await {
            Ok(true) => {
                log!("swept {} to {refund}", amount(value));
                // The reserve is sized from a quote, so a quote far above the real price leaves a large
                // part of it behind. Report that, so the caller keeps the key; an unreadable balance is
                // assumed to be such a case.
                let keep_key = match p.get_balance(sender).latest().await {
                    Ok(left) => {
                        log!(
                            "left at {sender}: {} (unused part of the sweep's fee reserve)",
                            amount(left)
                        );
                        keep_leftover(balance, value, left)
                    }
                    Err(_) => true,
                };
                return Ok((value, keep_key));
            }
            Ok(false) => {
                last = format!(
                    "sweep tx {hash} did not take effect: another tx with nonce {nonce} was mined, or it reverted"
                )
            }
            Err(err) => {
                last = err;
                floor = bump((max_fee, tip));
            }
        }
    }
    Err(format!("gave up after {SWEEP_TRIES} attempts: {last}"))
}

/// Whether `left`, what stayed at the sender after a sweep of `value` from `balance`, is worth keeping the
/// key for: more than `LEFTOVER_KEEP_RATIO` times the fee the sweep actually paid.
fn keep_leftover(balance: U256, value: U256, left: U256) -> bool {
    let paid = balance.saturating_sub(value).saturating_sub(left);
    left > paid * U256::from(LEFTOVER_KEEP_RATIO)
}

/// Poll for the sweep's fate: Ok(true) mined and succeeded; Ok(false) reverted, or `nonce` was used by
/// another tx; Err if neither happened within `SWEEP_WAIT`.
async fn mined(p: &impl Provider, hash: B256, sender: Address, nonce: u64) -> Result<bool, String> {
    let deadline = Instant::now() + SWEEP_WAIT;
    while Instant::now() < deadline {
        if let Ok(Some(r)) = p.get_transaction_receipt(hash).await {
            return Ok(r.status());
        }
        if p.get_transaction_count(sender)
            .latest()
            .await
            .is_ok_and(|n| n > nonce)
        {
            // The nonce is used; ours may have been mined between the two calls, so look once more.
            return Ok(matches!(p.get_transaction_receipt(hash).await, Ok(Some(r)) if r.status()));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(format!(
        "sweep tx {hash} not mined within {} s",
        SWEEP_WAIT.as_secs()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn deploy_code_layout() {
        let rec = [0xefu8; 152]; // starts with 0xEF on purpose: the 0x00 prefix must protect it
        let code = deploy_code(&rec);
        assert_eq!(&code[..3], &[0x61, 0x00, 0x99]); // PUSH2 153 = 1 + 152
        assert_eq!(code[10], 0x00); // the copy offset 0x0a lands exactly on the STOP byte
        assert_eq!(&code[11..], &rec);
        assert!(holds_record(&code[10..], &rec));
        assert!(
            !holds_record(&code[11..], &rec)
                && !holds_record(&[], &rec)
                && !holds_record(&code[10..code.len() - 1], &rec)
        );
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
        let r = FundRequest {
            sender: address!("00000000000000000000000000000000000000aa"),
            chain_id: 4153,
            required_wei: U256::from(7),
            refund: Address::ZERO,
        };
        assert_eq!(
            r.uri(),
            "ethereum:0x00000000000000000000000000000000000000AA@4153?value=7"
        );
    }

    #[test]
    fn scrub_hides_raw_and_normalized_urls() {
        let s = secret_forms(&["https://rpc.x/key/SECRET", ""]);
        assert!(
            !scrub(
                "error sending request for url (https://rpc.x/key/SECRET)".into(),
                &s
            )
            .contains("SECRET")
        );
        // reqwest prints the parsed URL: lowercase scheme and host, default port dropped.
        let s = secret_forms(&["HTTPS://RPC.X:443/key/SECRET"]);
        assert!(
            !scrub(
                "error sending request for url (https://rpc.x/key/SECRET)".into(),
                &s
            )
            .contains("SECRET")
        );
        // A bare host gets a trailing slash when parsed; the unparsed form must not leave it behind.
        let s = secret_forms(&["http://SECRET.example"]);
        assert_eq!(
            scrub("for url (http://secret.example/)".into(), &s),
            "for url (<rpc>)"
        );
    }

    #[test]
    fn budget_caps() {
        assert!(budget(1_000_000, 1_000_000_000, false).is_ok());
        assert!(budget(1_000_000, MAX_FEE_CAP + 1, false).is_err());
        assert!(budget(1_000_000, MAX_FEE_CAP + 1, true).is_ok());
    }

    #[test]
    fn tip_is_capped_by_base_fee() {
        assert_eq!(
            fees_from(30_000_000_000, 2_000_000_000),
            (62_000_000_000, 2_000_000_000)
        ); // below cap: kept
        assert_eq!(
            fees_from(1_000_000, 1_000_000_000),
            (2_000_000 + TIP_CAP_FLOOR, TIP_CAP_FLOOR)
        ); // L2: floored cap
        assert_eq!(
            fees_from(50_000_000_000, 80_000_000_000),
            (150_000_000_000, 50_000_000_000)
        ); // cap = base
    }

    #[test]
    fn bump_is_at_least_12_5_percent() {
        assert_eq!(bump((800, 80)), (900, 90));
        assert_eq!(bump((1, 1)), (2, 2)); // rounded up
        assert_eq!(bump((0, 0)), (0, 1)); // a zero tip still rises
    }

    #[test]
    fn leftover_keeps_the_key_only_when_the_quote_was_far_too_high() {
        let u = |n: u64| U256::from(n);
        // Normal: quote = 2 x price, so reserve 200 pays 100 and 100 stays: not worth a printed key.
        assert!(!keep_leftover(u(1_000), u(800), u(100)));
        // Doubled retry reserve: about three fees stay.
        assert!(!keep_leftover(u(1_000), u(700), u(225)));
        // Quote 100 x price: 99 of every 100 reserve wei stay.
        assert!(keep_leftover(u(10_000), u(0), u(9_900)));
    }

    /// A well-formed 2-of-2 record (passphrase and paper): 26 header bytes, 1 masked share, nonce, ciphertext.
    fn record_bytes() -> Vec<u8> {
        let mut r = vec![2, 0, 0, 4, 0, 3]; // version 2, m = 1024 KiB, t = 3
        r.extend([0; 16]); // salt
        r.extend([2, 2, 1, 3]); // k = 2, n = 2, kinds passphrase and paper
        r.resize(26 + 32 + 12 + 49, 0xab);
        r
    }

    #[test]
    fn record_parsing() {
        let hex = alloy::hex::encode(record_bytes());
        assert_eq!(parse_record(&format!("0x{hex}\n")).unwrap(), record_bytes());
        assert!(parse_record(&hex).is_err()); // no 0x
        assert!(parse_record(&format!("0x{hex}00")).is_err()); // one byte too long
        assert!(parse_record(&format!("0x{hex}zz")).is_err()); // not hex
        assert!(parse_record(&format!("0x01{}", &hex[2..])).is_err()); // wrong version byte
    }
}
