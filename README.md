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



