# publish (Ethereum Private Note)

Publishes a `record.hex` (from `vault`; see `SPEC.md`) as the runtime code of a new contract,
paying gas from a throwaway key that exists only in memory. Only public data goes on chain.

    cargo run --offline --locked -p epn-publish -- [--verify-rpc <url>] [--confirmations <n>] [--allow-high-fees] \
        <rpc-url> <record.hex> <refund-address>

Missing arguments are prompted for; extra ones are refused. It checks the record with the same validator
`recover` uses (`epn-core`: version `02`, 2 <= k <= n <= 5, known share kinds, at most one passphrase share,
exactly `85 + n + 32*c` bytes, Argon2 cost within SPEC's bounds), so it never publishes a record that
`recover` would refuse. It prints its **record id** (first 8 bytes of
SHA-256 over the record bytes, hex: the same id as on the recovery sheet), then the throwaway address and an
`ethereum:` URI, waits (15 min) for the funds, and deploys the record. As soon as the deploy succeeds it prints
the chain id, the record's address and the record id for the recovery sheet (even if a later step fails), then
reads the code back and sweeps the leftover ETH to the refund address. Amounts are shown in ETH and wei.

**Storage:** the contract's code is `0x00 || record`, created from the throwaway key at nonce 0, so the
address is `keccak256(rlp([sender, 0]))[12..]`. No contract has to exist on the chain beforehand and nothing
is compiled. Read it with `cast code <address>`. The largest record (250 bytes) gives 251 bytes of code,
far below the EIP-170 limit of 24576. The creation code and the reason for the `00` byte are in
`SPEC.md` ("On-chain storage").

**Tests:** `cargo test --offline --locked -p epn-publish` (unit + anvil end-to-end, including the binary under
Ctrl-C, a stuck deploy, RPC outages and a deploy mined after the run gave up; the anvil tests skip if `anvil`
is not installed).

## Safety behaviour

- **Every exit after funding sweeps** whatever is left (best effort; the error reports both outcomes). On a
  funding timeout, partial funds are swept back too, and the leftover dust is reported.
- **Ctrl-C, SIGTERM and closing the terminal (SIGHUP)** stop the run and sweep before exiting. A second Ctrl-C
  during the sweep abandons it.
- **What it cannot catch:** SIGKILL, an out-of-memory kill, power loss or sleep end the process without
  printing the key (the signal handling is Unix only, and with SIGHUP the terminal may already be gone).
  The RPC replies are bounded by a 20 s timeout but not by size, and redirects are refused.
- **The sweep replaces a stuck deploy.** It uses the latest *mined* nonce and balance, fees at least 12.5 %
  above the deploy's, and a value that leaves room for its own fee. It retries (re-reading the chain each
  time) on "nonce too low", an underpriced replacement, a sweep that stays unmined for 90 s (fee raised
  another 12.5 %) and insufficient funds (e.g. an L2 data fee: fee reserve doubled).
- **Nonce 0 decides the address.** The deploy is always sent with nonce 0, and the key sends nothing else but
  the sweep. If the sweep replaced a stuck deploy, nothing is stored and the run reports the failure. If the deploy was mined anyway, the next check finds the record at the address and says it is stored. If the run gave up
  on a deploy (timeout, Ctrl-C) that was mined anyway, it checks the code at the address once more after the
  sweep and, if it holds the record, prints the recovery-sheet block and says the record *is* stored.
- **RPC errors are retried** while waiting for funds (until the 15-minute deadline) and while waiting for the
  deploy's receipt, so one failed call never ends the run or makes the sweep replace a deploy being mined.
- **Last resort: the throwaway private key is printed to stderr** when ETH may be at the throwaway address, or
  on its way there, and the sweep did not finish: the sweep failed or was abandoned, the run crashed, or it
  ended before the funds arrived (a payment may still be in flight; the error then says *do not send funds
  to <address>*). That key only ever holds this run's gas money and printing it is the only way to recover
  that money; it is never written to disk. A normal run never prints it.
- The refund address needs a `0x` prefix, a valid EIP-55 checksum if mixed-case, and must have **no code**
  (a contract could make the fixed-gas sweep fail). It is echoed next to the funding request.
- The funding request is (gas limits + sweep) x max fee x **2**: the headroom covers fee moves and L2 data fees
  that gas estimates omit. Fees are re-quoted after funding arrives; if the new total is higher you are asked
  again. Quotes above 500 gwei/gas or 0.5 ETH total are refused unless `--allow-high-fees`. Max fee =
  2 x base fee + tip; the tip is capped at max(base fee, 0.01 gwei), because it is really paid.
- The deploy must reach `--confirmations` within 180 s plus 30 s per confirmation. The read-back compares the
  code byte for byte with `0x00 || record`, on `--verify-rpc` when given.
- The URI is `ethereum:<sender>@<chain id>?value=<wei>`; check the chain id in your wallet.
- Legacy (non-EIP-1559) chains are unsupported. The RPC URL is never printed (it may hold an API key); error
  text is scrubbed of it both as given and as the HTTP library prints it after normalising.

## What a lying RPC can and cannot do

It **cannot** learn or steal anything secret: only the public record and a throwaway key's signed txs pass
through it, and the key never leaves the process. It **can** censor or delay (the run fails, leftovers are swept
if the RPC allows), quote inflated fees (bounded by the caps above), or claim a record is stored when it is not.
Use `--verify-rpc` (an independent node, used only for the read-back) and `--confirmations` to reduce that last
risk. The recovery sheet should always be re-checked with `cast code` against a node you trust.

## Dependencies

alloy is used with `default-features = false` (HTTP provider, local signer, native-tls), which
avoids the rustls -> aws-lc-sys C build. On Linux, native-tls needs the system OpenSSL for https RPCs.
`core/` and `recover/` do not depend on alloy; `publish` depends on `epn-core` only for the record check and the
record id. `libc` is a signal handler that only sets a flag (tokio's `signal` feature would need two more
vendored crates).
