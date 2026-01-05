# `@pbnjam/bandersnatch-vrf`

Verifiable Random Functions (VRFs) over the Bandersnatch curve.

This package builds on `@pbnjam/bandersnatch` and provides:

- **IETF VRF** (RFC-9381-style) prover/verifier
- **Pedersen VRF** prover/verifier (with blinding)
- **Ring VRF** prover/verifier (Pedersen VRF + KZG-based ring membership proofs), including a WASM-backed variant
- **Hash-to-curve / nonce / challenge utilities** used by the VRF schemes

## Installation

This repository uses Bun workspaces. From the monorepo root:

```bash
bun install
```

## Usage

### Command-Line Interface (CLI)

The package provides a CLI for proving and verifying VRF proofs using JSON file inputs.

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
  "srsFilePath": "./test-data/srs/zcash-srs-2-11-compressed.bin",
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
  "srsFilePath": "./test-data/srs/zcash-srs-2-11-compressed.bin",
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

  // Verifiers
  IETFVRFVerifier,
  PedersenVRFVerifier,
  RingVRFVerifier,
  RingVRFVerifierWasm,

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

### IETF VRF (RFC-9381-style)

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

Main entry points:

- **Prover**: `new RingVRFProver(srsFilePath)` then `prove(secretKey, input)`
- **Verifier**: `new RingVRFVerifier(srsFilePath)` then `verify(ringKeys, input, serializedResult, auxData?)`

Serialization helpers:

- `RingVRFProver.serialize(result)` → `Uint8Array`
- `RingVRFProver.deserialize(bytes)` → `RingVRFResult`

WASM-backed variants are also exported:

- `RingVRFProverWasm`
- `RingVRFVerifierWasm`

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

From `packages/bandersnatch-vrf`:

```bash
bun run test
```

```bash
bun run build
```

## Notes

- Many functions operate on **compressed curve points** (`Uint8Array`, 32 bytes) and scalars in **little-endian** form, matching the in-repo codec expectations.
- For Ring VRF, you must provide a compatible **SRS file** path when constructing prover/verifier instances.






