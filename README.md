# Nexus Client

**Lend your GPU. Earn GNN.**

The Nexus Client connects your self-hosted LLM to the [Nexus compute
network](https://ghostnn.ai/nexus-client). You run an eligible open model
locally; the client pulls inference jobs from the gateway, serves them
through your local inference server, and you earn GNN (Solana) for every
metered token you generate.

This repo is the **complete source** of the binary you run. Build it
yourself or download a release — either way you can see exactly what
touches your machine and your keys.

## How it works

```
your GPU ── Ollama / vLLM / llama.cpp (any OpenAI-compatible server)
                │  http://localhost:11434/v1
                ▼
        ┌──────────────┐   outbound wss:// (no port-forwarding)
        │ nexus-client │ ─────────────────────────────────────────▶ gateway
        └──────────────┘   pulls jobs · streams results · earns GNN
```

- **Outbound-only.** The client dials the gateway over WebSocket. Nothing
  ever connects *into* your machine; no ports to open.
- **Your keys stay local.** `init` generates an Ed25519 node identity and
  a Solana wallet under `~/.nexus-client/` (mode 0600). The wallet's
  private key is never transmitted — auth is a challenge signature.
- **Metering happens at the gateway.** Earnings are computed from tokens
  the gateway itself counts as they stream through it. The client can't
  inflate them, and neither can anyone else's client.

## Eligible models

| Model | Sizes | Approx. VRAM |
|---|---|---|
| Hermes 3 | 8B | ~10 GB (Q8) / ~6 GB (Q4) |
| Kimi K2 | large MoE | 2×80 GB-class, or hosted |
| Qwen 2.5 | 7B / 14B / 32B | ~8 / ~12 / ~24 GB (Q4) |

## Quickstart

```sh
# 1. Pull an eligible model with Ollama. The served model name must match
#    the --model you pass to init exactly.
ollama pull llama3.2

# 2. Initialize — creates the node key + config. Import a GNN-funded wallet
#    (path to a solana-keygen JSON file or a base58 64-byte secret), or omit
#    --wallet to generate a fresh one and fund the printed address.
nexus-client init --model llama3.2 --wallet import ./wallet.json

# 3. Stake GNN on-chain to the network treasury (mainnet — 1 GNN minimum).
#    This sends the transfer and records it so the gateway accepts your node.
nexus-client stake --amount 1

# 4. Start serving inference jobs and earning
nexus-client start

# Check earnings any time (needs the wallet that owns the node)
nexus-client earnings
```

Full step-by-step guide with diagrams: https://ghostnn.ai/nexus-client/docs

Config lives at `~/.nexus-client/config.toml`:

```toml
model = "hermes-3"
upstream = "http://localhost:11434/v1"
gateway = "wss://nexus.ghostnn.ai/api/compute/node"
```

## Build from source

```sh
cargo build --release
./target/release/nexus-client --help
```

Requires Rust 1.93+. No system OpenSSL needed (rustls).

## Verifying releases

Every release ships a `SHA256SUMS` file generated in CI. Verify your
download:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Release binaries are built by the GitHub Actions workflow in
[`.github/workflows/release.yml`](.github/workflows/release.yml) from the
tagged source — the build is reproducible from what you see here.

## Security model (short version)

| Concern | Answer |
|---|---|
| Can the network spend my wallet? | No. The wallet key never leaves your disk; it only *receives* payouts and signs the stake transfer you make yourself. |
| Can jobs run code on my machine? | No. Jobs are chat-completion payloads forwarded to your local inference server over HTTP. The client never executes job content. |
| What can the gateway see? | The prompts/completions of jobs it routes to you (it has to — it meters them), your node pubkey, wallet pubkey, model name, and context length. |
| What gets me slashed? | Serving a different model than you registered (canary checks), or extended downtime mid-job. Schedule: see ghostnn.ai/nexus-client. |

## License

MIT or Apache-2.0, at your option.

## `nexus-client work` — AgenC provider mode (v0.1.7)

Beyond serving compute jobs (`start`), a node can now earn **SOL** as an AgenC
provider. `nexus-client work` registers your node + bonds, discovers open jobs on
the Nexus board, claims one it can profitably take, drives a delegated Builder
session to build the app on your own inference, and submits it on-chain — all
signed locally with your node wallet. When the requester publishes your draft,
the escrow settles to you.

```bash
nexus-client work            # register → discover → claim → build → submit
```

Config lives in `~/.nexus-client/config.toml` under `[agenc]` (build API URL,
Solana RPC, reward floor). The worker signs every on-chain tx locally and asserts
the program id + instruction before signing — it never hands its key to a server.
