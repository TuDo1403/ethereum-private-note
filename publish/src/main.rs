//! `publish [flags] <rpc-url> <record.hex> <refund-address>`; missing positionals are prompted for.
//! Flags: `--verify-rpc <url>` (second RPC, read-back only), `--confirmations <n>`, `--allow-high-fees`.
use epn_publish::{FundRequest, Options, amount, parse_address, parse_record};
use std::io::{self, Write};
use std::time::Duration;

const FUND_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// `println!` that ignores a closed stdout instead of panicking: once funds may have arrived, the run
/// must reach its sweep even if the terminal is gone.
macro_rules! say {
    ($($t:tt)*) => {{ let _ = writeln!(io::stdout(), $($t)*); }};
}

fn ask(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line.trim().to_string())
}

fn run() -> Result<(), String> {
    let (mut verify, mut confirmations, mut allow_high_fees) = (None, 1u64, false);
    let mut positional = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--verify-rpc" => verify = Some(args.next().ok_or("--verify-rpc needs a URL")?),
            "--confirmations" => confirmations = args.next().and_then(|v| v.parse().ok()).ok_or("--confirmations needs a number")?,
            "--allow-high-fees" => allow_high_fees = true,
            f if f.starts_with("--") => return Err(format!("unknown flag {f}")),
            _ => positional.push(a),
        }
    }
    if positional.len() > 3 {
        return Err(format!("unexpected extra argument #{}; usage: publish [flags] <rpc-url> <record.hex> <refund-address>", positional.len()));
    }
    let mut positional = positional.into_iter();
    let mut arg = |prompt: &str| positional.next().map_or_else(|| ask(prompt), Ok);
    let rpc = arg("RPC URL: ")?;
    let path = arg("Path to record.hex: ")?;
    let refund = parse_address(&arg("Refund address (0x..., leftover ETH goes here): ")?)?;
    let record = parse_record(&std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?)?;

    let opts = Options { rpc_url: &rpc, verify_rpc_url: verify.as_deref(), refund, fund_timeout: FUND_TIMEOUT, confirmations, allow_high_fees };
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    // From here on, Ctrl-C / closing the terminal stops the run through its sweep instead of killing it.
    #[cfg(unix)]
    epn_publish::catch_signals();
    let out = rt.block_on(epn_publish::publish(&opts, &record, |r: &FundRequest| {
        // QR rendering skipped on purpose: most wallets accept the URI or address as text.
        say!("\nFund this THROWAWAY address (its key exists only in this process):");
        say!("  {}\n  {}", r.sender, r.uri());
        say!("  needs {} on chain {}; leftovers are refunded to {}", amount(r.required_wei), r.chain_id, r.refund);
        say!("  waiting up to {} min. If this program stops before it says \"funded\", do not send.", FUND_TIMEOUT.as_secs() / 60);
    }))?;

    // The recovery-sheet block (chain id, address, record id) was printed as soon as the deploy succeeded.
    say!("\nPublished and read back. Swept {} to {}.", amount(out.swept), refund);
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        let _ = writeln!(io::stderr(), "error: {e}");
        std::process::exit(1);
    }
}
