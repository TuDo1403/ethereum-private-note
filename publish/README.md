# publish (Ethereum Private Note)

Publishes a 147-byte `record.hex` (from `vault`) as the runtime code of a new contract, paying gas from a
throwaway key that exists only in memory. Only public data goes on chain.

    cargo run --offline --locked -p epn-publish -- [--verify-rpc <url>] [--confirmations <n>] [--allow-high-fees] \
        <rpc-url> <record.hex> <refund-address>

Missing arguments are prompted for. It prints the throwaway address and an `ethereum:` URI, waits (15 min)
for the funds, deploys the record, reads the code back, sweeps the leftover ETH to the refund address, then
prints the chain id and the record's address for the recovery sheet.

**Storage:** the contract's code is `0x00 || record`, created from the throwaway key at nonce 0, so the
address is `keccak256(rlp([sender, 0]))[12..]`. No contract has to exist on the chain beforehand and nothing
is compiled. Read it with `cast code <address>`. The creation code and the reason for the `00` byte are in
`SPEC.md` ("On-chain storage").

**Tests:** `cargo test --offline --locked -p epn-publish` (unit + anvil end-to-end; the anvil tests skip if
`anvil` is not installed).

## Safety behaviour

- **Every exit after funding sweeps** whatever is left (best effort; the error reports both outcomes). On a
  funding timeout, partial funds are swept back too. The sweep retries with a larger fee reserve if the node
  rejects it (e.g. an L2 data fee).
- The refund address needs a `0x` prefix, a valid EIP-55 checksum if mixed-case, and must have **no code**
  (a contract could make the fixed-gas sweep fail). It is echoed next to the funding request.
- The funding request is (gas limits + sweep) x max fee x **2**: the headroom covers fee moves and L2 data fees
  that gas estimates omit. Fees are re-quoted after funding arrives; if the new total is higher you are asked
  again. Quotes above 500 gwei/gas or 0.5 ETH total are refused unless `--allow-high-fees`.
- The URI is `ethereum:<sender>@<chain id>?value=<wei>`; check the chain id in your wallet.
- Legacy (non-EIP-1559) chains are unsupported. The RPC URL is never printed (it may hold an API key).

## What a lying RPC can and cannot do

It **cannot** learn or steal anything secret: only the public record and a throwaway key's signed txs pass
through it, and the key never leaves the process. It **can** censor or delay (the run fails, leftovers are swept
if the RPC allows), quote inflated fees (bounded by the caps above), or claim a record is stored when it is not.
Use `--verify-rpc` (an independent node, used only for the read-back) and `--confirmations` to reduce that last
risk. The recovery sheet should always be re-checked with `cast code` against a node you trust.

## Dependencies

alloy is used with `default-features = false` (HTTP provider, local signer, native-tls), which
avoids the rustls -> aws-lc-sys C build. On Linux, native-tls needs the system OpenSSL for https RPCs.
`core/` and `recover/` do not depend on alloy.
