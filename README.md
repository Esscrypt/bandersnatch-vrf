# `@pbnjam/bandersnatch-vrf`

[![Tests](https://github.com/Esscrypt/peanutbutterandjam/actions/workflows/verify.yml/badge.svg)](https://github.com/Esscrypt/peanutbutterandjam/actions/workflows/verify.yml) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Production-grade Verifiable Random Functions (VRFs) on the Bandersnatch curve** for the [JAM](https://graypaper.com/) protocol. This package is part of [Peanut Butter AND JAM (PBNJ)](https://github.com/Esscrypt/peanutbutterandjam) and extends `@pbnjam/bandersnatch` with:

- **IETF VRF** — RFC 9381–style prover/verifier (Elligator2 hash-to-curve)
- **Pedersen VRF** — Prover/verifier with blinding
- **Ring VRF** — Pedersen VRF plus KZG ring membership proofs; **WASM** and **W3F** (native Rust) backends
- **Crypto utilities** — Hash-to-curve, nonce generation, challenge hashing (reusable building blocks)

| Resource | Link |
|----------|------|
| Monorepo docs | [Getting started](https://www.peanutbutterandjam.xyz/getting-started) |
| Specification | [Gray Paper](https://graypaper.com/) |
| Changelog (this package) | [CHANGELOG.md](CHANGELOG.md) |
| API (this package) | This README; run `bun run docs` for TypeDoc output |

---

## Table of contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Getting started](#getting-started)
- [Usage](#usage)
- [Schemes](#schemes)
- [Crypto utilities](#crypto-utilities)
- [Development](#development)
- [Notes](#notes)
- [Contributing](#contributing)
- [License](#license)
- [Security](#security)
- [Support and references](#support-and-references)
- [Changelog](CHANGELOG.md)

---

## Prerequisites

- **[Bun](https://bun.sh/)** (v1.3.x or later) — primary runtime and package manager
- **Rust** (stable) — only if using the **W3F** Ring VRF backend (native `rust-ring-proof` module)

## Installation

From the [PBNJ monorepo](https://github.com/Esscrypt/peanutbutterandjam) root:

```bash
git clone https://github.com/Esscrypt/peanutbutterandjam.git
cd peanutbutterandjam
git submodule update --init --recursive
bun install
```

To use this package from another workspace in the monorepo, depend on `@pbnjam/bandersnatch-vrf` in your `package.json`; the workspace will resolve it.

## Getting started

### SRS file (Ring VRF only)

Ring VRF requires a **Structured Reference String (SRS)** in uncompressed arkworks format. The package includes a test SRS for rings up to size 2¹¹:

| Item | Value |
|------|--------|
| Path (from package root) | `test-data/srs/zcash-srs-2-11-uncompressed.bin` |
| In monorepo | `packages/bandersnatch-vrf/test-data/srs/zcash-srs-2-11-uncompressed.bin` |

Pass the resolved path to the `RingVRFProver*` and `RingVRFVerifier*` constructors. From other packages (e.g. `infra/node`), resolve relative to the repo root or your app (e.g. `path.join`).

### Ring VRF: W3F vs WASM

| Backend | Classes | When to use |
|---------|---------|--------------|
| **WASM** | `RingVRFProverWasm`, `RingVRFVerifierWasm` | Any environment; no native build. |
| **W3F** | `RingVRFProverW3F`, `RingVRFVerifierW3F` | Higher throughput; requires `bun run build:native` (Rust). |

Both backends use the same SRS and produce **interchangeable** proofs (same gamma/beta; verifiers accept proofs from either).

### Simple usage: W3F prover and verifier

```ts
import path from 'node:path'
import { RingVRFProverW3F, RingVRFVerifierW3F } from '@pbnjam/bandersnatch-vrf'
import { hexToBytes } from 'viem'

const srsFilePath = path.join(
  __dirname,
  'test-data/srs/zcash-srs-2-11-uncompressed.bin',
)

async function main() {
  const prover = new RingVRFProverW3F(srsFilePath)
  await prover.init()
  const verifier = new RingVRFVerifierW3F(srsFilePath)
  await verifier.init()

  const secretKey = hexToBytes('0x...')   // 32 bytes
  const ringInput = {
    input: hexToBytes('0x...'),           // VRF input
    auxData: hexToBytes('0x...'),        // optional
    ringKeys: [/* Uint8Array of compressed pubkeys, 32 bytes each */],
    proverIndex: 0,                      // index of prover's key in ringKeys
  }

  const result = prover.prove(secretKey, ringInput)
  // result.gamma, result.proof (pedersenProof, ringCommitment, ringProof)

  const ok = verifier.verify(
    ringInput.ringKeys,
    ringInput,
    { gamma: result.gamma, proof: result.proof },
    ringInput.auxData,
  )
  console.log('Verified:', ok)
}
```

### Simple usage: WASM prover and verifier

```ts
import path from 'node:path'
import { RingVRFProverWasm, RingVRFVerifierWasm } from '@pbnjam/bandersnatch-vrf'
import { hexToBytes } from 'viem'

const srsFilePath = path.join(
  __dirname,
  'test-data/srs/zcash-srs-2-11-uncompressed.bin',
)

async function main() {
  const prover = new RingVRFProverWasm(srsFilePath)
  await prover.init()
  const verifier = new RingVRFVerifierWasm(srsFilePath)
  await verifier.init()

  const secretKey = hexToBytes('0x...')
  const ringInput = {
    input: hexToBytes('0x...'),
    auxData: hexToBytes('0x...'),
    ringKeys: [/* Uint8Array, 32 bytes each */],
    proverIndex: 0,
  }

  const result = prover.prove(secretKey, ringInput)
  const ok = verifier.verify(
    ringInput.ringKeys,
    ringInput,
    { gamma: result.gamma, proof: result.proof },
    ringInput.auxData,
  )
  console.log('Verified:', ok)
}
```

**Serialization:** Use `RingVRFProver.serialize(result)` for a `Uint8Array` and `RingVRFProver.deserialize(bytes)` to reconstruct a result. Verifiers accept either the raw `{ gamma, proof }` or the deserialized value.

---

## Usage

You can use the **CLI** (JSON files) or the **programmatic API** (see [Getting started](#getting-started) and [Import the public API](#import-the-public-api)).

### Command-Line Interface (CLI)

The CLI proves and verifies VRF proofs using JSON input/output files.

#### Basic Usage

```bash
# Prove IETF VRF
bandersnatch-vrf prove ietf --input input.json --output proof.json

# Verify IETF VRF
bandersnatch-vrf verify ietf --input verify.json

# Prove Pedersen VRF
bandersnatch-vrf prove pedersen --input input.json --output proof.json

# Verify Pedersen VRF
bandersnatch-vrf verify pedersen --input verify.json

# Prove Ring VRF
bandersnatch-vrf prove ring --input input.json --output proof.json

# Verify Ring VRF
bandersnatch-vrf verify ring --input verify.json
```

#### JSON Input Formats

**IETF VRF Prove Input** (`input.json`):
```json
{
  "secretKey": "0x...",
  "input": "0x...",
  "auxData": "0x..." // optional
}
```

**IETF VRF Prove Output** (`proof.json`):
```json
{
  "gamma": "0x...",
  "proof": "0x..."
}
```

**IETF VRF Verify Input** (`verify.json`):
```json
{
  "publicKey": "0x...",
  "input": "0x...",
  "proof": "0x...",
  "auxData": "0x..." // optional
}
```

**Pedersen VRF Prove Input** (`input.json`):
```json
{
  "secretKey": "0x...",
  "input": "0x...",
  "auxData": "0x..." // optional
}
```

**Pedersen VRF Prove Output** (`proof.json`):
```json
{
  "gamma": "0x...",
  "proof": "0x..."
}
```

**Pedersen VRF Verify Input** (`verify.json`):
```json
{
  "input": "0x...",
  "gamma": "0x...",
  "proof": "0x...",
  "auxData": "0x..." // optional
}
```

**Ring VRF Prove Input** (`input.json`):
```json
{
  "secretKey": "0x...",
  "input": "0x...",
  "auxData": "0x...", // optional
  "ringKeys": ["0x...", "0x...", ...],
  "proverIndex": 0,
  "srsFilePath": "./test-data/srs/zcash-srs-2-11-uncompressed.bin",
  "useWasm": false // optional, default: false
}
```

**Ring VRF Prove Output** (`proof.json`):
```json
{
  "gamma": "0x...",
  "hash": "",
  "proof": {
    "pedersenProof": "0x...",
    "ringCommitment": "0x...",
    "ringProof": "0x...",
    "proverIndex": 0
  },
  "serialized": "0x..."
}
```

**Ring VRF Verify Input** (`verify.json`):
```json
{
  "ringKeys": ["0x...", "0x...", ...],
  "input": "0x...",
  "serializedResult": "0x...",
  "auxData": "0x...", // optional
  "srsFilePath": "./test-data/srs/zcash-srs-2-11-uncompressed.bin",
  "useWasm": false // optional, default: false
}
```

#### Running the CLI

The CLI can be run in several ways:

1. **Using Bun directly**:
```bash
bun run packages/bandersnatch-vrf/src/cli.ts prove ietf --input input.json
```

2. **After building the binary**:
```bash
bun run build:bin
./bin/bandersnatch-vrf prove ietf --input input.json
```

3. **Programmatically**:
```ts
import { proveIETF, verifyIETF } from '@pbnjam/bandersnatch-vrf'

await proveIETF('input.json', 'proof.json')
await verifyIETF('verify.json')
```

### Import the public API

```ts
import {
  // Provers
  IETFVRFProver,
  PedersenVRFProver,
  RingVRFProver,
  RingVRFProverWasm,
  RingVRFProverW3F,

  // Verifiers
  IETFVRFVerifier,
  PedersenVRFVerifier,
  RingVRFVerifier,
  RingVRFVerifierWasm,
  RingVRFVerifierW3F,

  // Crypto helpers
  elligator2HashToCurve,
  generateNonceRfc8032,
  generateChallengeRfc9381,
  pointToHashRfc9381,

  // CLI functions
  proveIETF,
  verifyIETF,
  provePedersen,
  verifyPedersen,
  proveRing,
  verifyRing,
  runCLI,
} from '@pbnjam/bandersnatch-vrf'
```

## Schemes

| Scheme | Prover | Verifier | Notes |
|--------|--------|----------|--------|
| IETF VRF | `IETFVRFProver` | `IETFVRFVerifier` | RFC 9381; Elligator2 hash-to-curve |
| Pedersen VRF | `PedersenVRFProver` | `PedersenVRFVerifier` | Blinded; no SRS |
| Ring VRF (WASM) | `RingVRFProverWasm` | `RingVRFVerifierWasm` | SRS required; no native build |
| Ring VRF (W3F) | `RingVRFProverW3F` | `RingVRFVerifierW3F` | SRS required; native Rust; faster |

### IETF VRF (RFC 9381)

- **Prover**: `IETFVRFProver.prove(secretKey, input, auxData?)` → `{ gamma, proof }`
- **Verifier**: `IETFVRFVerifier.verify(publicKey, input, proof, auxData?)` → `boolean`

Key details reflected in the implementation:

- The prover uses Elligator2 hash-to-curve via `IETFVRFProver.hashToCurve(...)`.
- Proofs are verified against a recomputed challenge using `generateChallengeRfc9381(...)`.

### Pedersen VRF

- **Prover**: `PedersenVRFProver.prove(secretKey, { input, auxData? })`
- **Verifier**: `PedersenVRFVerifier.verify(input, gamma, proof, auxData?)`

The Pedersen proof structure follows the code-defined layout:

- `PedersenVRFProof`: `(Y_bar, R, O_k, s, s_b)` as byte arrays.

### Ring VRF (KZG ring membership)

Ring VRF combines:

- A Pedersen VRF proof (blinded)
- A ring membership proof over a ring of public keys (KZG commitments)

SRS: use the same SRS file for all Ring VRF provers/verifiers, e.g. `test-data/srs/zcash-srs-2-11-uncompressed.bin` (see [Getting started](#getting-started)).

Main entry points:

- **Prover**: `new RingVRFProver(srsFilePath)` then `prove(secretKey, input)` (TypeScript/KZG). Or use **W3F** / **WASM** backends: `RingVRFProverW3F`, `RingVRFProverWasm` (see [Simple usage](#simple-usage-w3f-prover-and-verifier) above).
- **Verifier**: `new RingVRFVerifier(srsFilePath)` then `verify(ringKeys, input, serializedResult, auxData?)`. Or `RingVRFVerifierW3F`, `RingVRFVerifierWasm`.

Serialization helpers:

- `RingVRFProver.serialize(result)` → `Uint8Array`
- `RingVRFProver.deserialize(bytes)` → `RingVRFResult`

WASM- and W3F-backed variants:

- **WASM**: `RingVRFProverWasm`, `RingVRFVerifierWasm` (ark-vrf WASM; no native build).
- **W3F**: `RingVRFProverW3F`, `RingVRFVerifierW3F` (native Rust; faster; requires `bun run build:native`).

## Crypto utilities

The `crypto/` exports are intended to be reusable building blocks:

- **Elligator2 / hash-to-curve** (`crypto/elligator2.ts`)
  - `elligator2HashToCurve(message: Uint8Array): CurvePoint`
  - `curvePointToNoble(point: CurvePoint): EdwardsPoint`
  - `compressPoint(point: CurvePoint): string`
  - plus helpers like `clearCofactor`, `isOnCurve`, `addPoints`, `scalarMultiply`, etc.
- **Nonce generation** (`crypto/nonce-rfc8032.ts`)
  - `generateNonceRfc8032(secretKey: Uint8Array, inputPoint: Uint8Array): Uint8Array`
- **Challenge / output hashing** (`crypto/rfc9381.ts`)
  - `generateChallengeRfc9381(...)`
  - `pointToHashRfc9381(...)`

## Development

From the package directory (`packages/bandersnatch-vrf`):

```bash
bun run build    # build package
bun run test     # run test suite
bun run build:native   # build Rust ring-proof module (optional; for W3F backend)
bun run docs     # generate API documentation (TypeDoc → docs/)
```

### Ring VRF benchmarks (WASM vs W3F)

The ring end-to-end test runs both **WASM** (ark-vrf-wasm) and **W3F** (native Rust when built, else WASM) prover and verifier and reports execution time for each.

**Command** (from `packages/bandersnatch-vrf`):

```bash
bun test src/__tests__/ring-end-to-end.test.ts
```

**Hardware** (machine used for the numbers below):

- **CPU**: Apple M4
- **Arch**: arm64
- **Cores**: 10

**Typical results** (2 test vectors, ring size 8):

| Vector | WASM prove | WASM verify | W3F prove | W3F verify |
|--------|------------|-------------|-----------|------------|
| 1      | ~1400 ms   | ~220 ms     | ~220 ms   | ~72 ms     |
| 2      | ~740 ms    | ~170 ms     | ~190 ms   | ~66 ms     |

W3F (native) is roughly **4–6× faster** on prove and **~3× faster** on verify. Both backends produce identical gamma/beta and verify successfully; WASM output is checked against the bandersnatch-vrf-spec test vectors.

## Notes

- **Data formats:** Compressed curve points are 32-byte `Uint8Array`s; scalars are **little-endian**, consistent with the JAM codec.
- **Ring VRF:** Prover and verifier constructors require a path to a compatible SRS file (see [SRS file](#srs-file-ring-vrf-only)).
- **Specification:** Ring VRF test vectors align with the bandersnatch-vrf-spec; IETF VRF follows [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html).

### W3F Ring VRF memory footprint

Calling `await prover.init()` / `await verifier.init()` on the W3F (native Rust) backend is a **one-time, upfront cost** that can consume several gigabytes of native process memory. For a full JAM validator ring of 1 023 keys, expect **~3–4 GB RSS** after initialisation.

**Why so large?**  
The `RingPiopParams::setup` step precomputes polynomial commitment data (Lagrange bases, KZG evaluations) for every validator public key in the ring. This data is allocated on the Rust heap inside the napi-rs native module and held for the lifetime of the process so that individual prove/verify calls are fast.

**What you will observe in `process.memoryUsage()`:**

| Field | Typical value | What it represents |
|-------|--------------|---------------------|
| `heapUsed` | ~500 MB | JavaScript objects (services, state, etc.) |
| `external` | ~100–150 MB | Node.js Buffers / TypedArrays |
| `rss` | ~3.5–4 GB | Total process RSS, includes Rust native heap |
| **Gap** (`rss − heap − external`) | **~3–3.5 GB** | **Rust ring-proof precomputed data** (not tracked by JS GC) |

The gap does **not** appear in `heapUsed` or `external` because napi-rs allocations bypass the JavaScript garbage collector entirely. This is expected behaviour, not a memory leak — the value is stable after init and does not grow with block count.

**Mitigation options:**
- Use the **WASM** backend (`RingVRFProverWasm`) if resident memory is a hard constraint; WASM linear memory is larger than V8's tracked `external` but the footprint profile differs.
- Initialise the prover and verifier **once** at process start and reuse them across all operations; re-initialising for every block or trace multiplies the cost.

---

## Contributing

This package is part of [Peanut Butter AND JAM (PBNJ)](https://github.com/Esscrypt/peanutbutterandjam) and is developed as a [submodule](https://github.com/Esscrypt/bandersnatch-vrf) with its own issue and PR templates. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and process. When opening issues or PRs in this repo: [Bug report](https://github.com/Esscrypt/bandersnatch-vrf/issues/new?template=bug_report.md), [Feature request](https://github.com/Esscrypt/bandersnatch-vrf/issues/new?template=feature_request.md), [PR template](.github/PULL_REQUEST_TEMPLATE.md).

---

## License

Licensed under the [Apache License 2.0](LICENSE). See [LICENSE](LICENSE) in this directory.

---

## Security

To report a security vulnerability, do **not** open a public issue. See [SECURITY.md](../../SECURITY.md) in the repository root for responsible disclosure.

---

## Support and references

- **JAM protocol and PBNJ:** [Gray Paper](https://graypaper.com/), [PBNJ docs](https://www.peanutbutterandjam.xyz/getting-started)
- **Issues and discussions:** [GitHub Issues](https://github.com/Esscrypt/peanutbutterandjam/issues)




