# DropKick sandbox

A local web page for playing with DropKick against a private `elementsd` regtest node.

```
cmake --build build --target elementsd
python3 dropkick_web/server.py            # then open http://127.0.0.1:8765/
```

Options: `--port`, `--elementsd <path>` (default `build/bin/elementsd`, or `$ELEMENTSD`),
`--datadir <dir>` (default `dropkick_web/.data`). Only the Python standard library and
the repository's `test/functional/test_framework` are used.

The server starts and stops its own node (RPC port 18884, P2P 18885, no peers). The node wallet
uses P2TR addresses, which DropKick leaves alone, so it keeps working after Q-day. Everything the
pages create — keys, outputs, commitments, reveals — is kept in `.data/state.json` next to the
node's datadir; "Reset chain" on the first page wipes both.

Pages:

- **Chain** — height, deployment status, mining, Q-day, reset.
- **Outputs** — lock funds in P2PKH (compressed or uncompressed key), P2WPKH, P2SH-P2WPKH, P2SH,
  P2WSH, or a BIP32 child; reuse one key across several types; spend an output the ordinary way.
- **Commit** — SHRINCS keys (random or from a seed), commit outputs into one aggregation batch,
  optional salvager and fee.
- **Reveal** — open commitments made under one key, stateful or stateless signature, state
  counter, fee; check with `testmempoolaccept` or broadcast, and see the decoded payload.
- **Transaction** — look up any transaction in the mempool or chain by txid, or pick one the
  sandbox made. Shows inputs and outputs with their roles (salvage payout, DropKick payload,
  rescued funds, commitment root, wallet change, fee) and what the transaction did in the
  sandbox. A reveal gets its payload decoded and its SHRINCS signature re-verified; a commitment
  transaction lists the roots it publishes. Every txid elsewhere on the site links here.

Q-day restarts the node with `-evbparams=dropkick:<next period boundary>::16:16` and mines until
the deployment is active. It cannot be undone except by resetting the chain.
