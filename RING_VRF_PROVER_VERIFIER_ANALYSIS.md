# Ring VRF: Prover/Verifier Performance Comparison

This document compares **prove** and **verify** execution times for the three Ring VRF backends (Pure TypeScript, WASM, and W3F native) and summarizes trade-offs: native build requirements, memory use, and portability.

---

## Test environment

All benchmarks in this document were produced on the following machine:

| Item | Value |
|------|--------|
| **CPU** | Apple M4 |
| **Architecture** | arm64 (aarch64) |
| **Cores** | 10 |
| **Runtime** | Bun (primary); Node.js compatible |
| **Ring size** | 8 |
| **Test vectors** | 2 (bandersnatch_sha-512_ell2_ring) |

Results are from a single run per backend. Timings may vary with OS load, thermal state, and runtime version. For reproducible numbers, run the commands in [How to reproduce](#how-to-reproduce) on equivalent hardware.

---

## Backend overview

| Backend | Prover | Verifier | Implementation |
|---------|--------|----------|----------------|
| **Pure TypeScript** | `RingVRFProver` | `RingVRFVerifier` | Full Plonk/KZG in TypeScript (`ring-kzg.ts`, `verifier/ring.ts`) |
| **WASM** | `RingVRFProverWasm` | `RingVRFVerifierWasm` | Rust compiled to WebAssembly (ark-vrf-wasm) |
| **W3F (native)** | `RingVRFProverW3F` | `RingVRFVerifierW3F` | Native Rust via napi-rs (`rust-ring-proof`) |

All three backends use the same SRS, produce **interchangeable** proofs (identical gamma/beta), and any verifier accepts proofs from any prover.

---

## Benchmark results

Typical prove and verify times on the test environment above:

| Backend | Prove (ms) | Verify (ms) | Notes |
|---------|------------|-------------|--------|
| **Pure TypeScript** | ~25 000–26 000 | ~4 700–5 000 | No native or WASM build; slowest. |
| **WASM** | ~740–1 400 | ~170–220 | No native build; moderate speed. |
| **W3F (native)** | ~190–220 | ~66–72 | Requires `bun run build:native`; fastest. |

**Per-vector (Pure TypeScript)** — from `bun test …/ring-end-to-end.test.ts` on the test environment above:

| Vector | Prove (ms) | Verify (ms) |
|--------|------------|-------------|
| 1 (bandersnatch_sha-512_ell2_ring) | 25 867 | 5 018 |
| 2 (bandersnatch_sha-512_ell2_ring) | 26 463 | 4 895 |

**Relative performance:**

- **Prove:** W3F is approximately 2–7× faster than WASM and **~100–130× faster** than Pure TypeScript.
- **Verify:** W3F is approximately 2.5–3× faster than WASM and **~70–75× faster** than Pure TypeScript.

Pure TypeScript is intended for tests, tooling, and environments where Rust or WASM cannot be built or loaded. For production throughput, use WASM or W3F.

---

## Backend comparison

### Pure TypeScript

- **Advantages:** No Rust toolchain or WASM; runs in any Bun/Node environment. Single codebase with the rest of the package; straightforward to debug and extend.
- **Disadvantages:** Prove ~25–26 s and verify ~5 s per call (dominated by field arithmetic and FFT in JavaScript).
- **Use when:** CI, one-off scripts, or environments that cannot load native or WASM; or when avoiding native/WASM is more important than speed.
- **Reproduce:** See [How to reproduce](#how-to-reproduce).

### WASM

- **Advantages:** No native compilation; single artifact; typically 2–7× faster prove and ~3× faster verify than Pure TypeScript.
- **Disadvantages:** Slower than W3F; WASM linear memory and startup overhead.
- **Use when:** You want better performance than Pure TypeScript without building the native module.
- **Reproduce:** See main README, “Ring VRF benchmarks (WASM vs W3F)”; or use CLI with `useWasm: true` and measure prove/verify.

### W3F (native)

- **Advantages:** Fastest: ~190–220 ms prove, ~66–72 ms verify in the table above. Best for high-throughput validators.
- **Disadvantages:** Requires Rust and `bun run build:native`; large one-time memory footprint after init (~3–4 GB RSS for a full ring; see README, “W3F Ring VRF memory footprint”).
- **Use when:** Production validators or any setting where latency and throughput matter and a native build is acceptable.
- **Reproduce:** After `bun run build:native`, run the native/W3F ring e2e tests; README benchmark section reports WASM vs W3F.

---

## How to reproduce

**Pure TypeScript** (from repository root):

```bash
bun test packages/bandersnatch-vrf/src/__tests__/ring-end-to-end.test.ts --timeout 300000
```

Look for lines of the form `Pure TS: prove … ms, verify … ms` in the output.

**WASM / W3F:**  
See the main [README section on Ring VRF benchmarks](README.md#ring-vrf-benchmarks-wasm-vs-w3f-vs-pure-typescript) for how to run the tests that report WASM and W3F timings. Use the same test file and environment for comparable results.

---

## Summary (reference)

| Backend | Prove | Verify | Native build? | Recommended use |
|---------|-------|--------|----------------|------------------|
| Pure TypeScript | ~25–26 s | ~5 s | No | Tests, tooling, no-Rust environments |
| WASM | ~0.7–1.4 s | ~0.17–0.22 s | No | Portability with moderate speed |
| W3F (native) | ~0.19–0.22 s | ~0.066–0.072 s | Yes | Production, maximum throughput |

For a shorter overview, see the [README section on Ring VRF benchmarks](README.md#ring-vrf-benchmarks-wasm-vs-w3f-vs-pure-typescript).

---

# JAM Specialized Components — Performance Analysis

This section benchmarks individual cryptographic and consensus-critical operations used across the JAM protocol, independent of the Ring VRF system. All operations were measured on the same test environment described at the top of this document (Apple M4, Bun runtime). Each operation was warmed up for 3 iterations and then measured over 20 iterations; **median** values are reported.

The benchmark script is located at `src/__tests__/jam-components-benchmark.ts` and can be reproduced with:

```bash
bun run packages/bandersnatch-vrf/src/__tests__/jam-components-benchmark.ts
```

---

## 1. Bandersnatch Curve Operations

Low-level elliptic curve arithmetic on the Bandersnatch Twisted Edwards curve, built on `@noble/curves`.

| Operation | Median | Notes |
|-----------|--------|-------|
| `scalarMultiply` (generator, GLV) | 0.544 ms | GLV with Shamir's trick; no precomputed table |
| `scalarMultiply` (generator, wNAF) | 0.111 ms | noble's cached wNAF table for `BASE` |
| `scalarMultiply` (arbitrary, GLV) | 0.540 ms | Half-width decomposition; ~2.2x faster than wNAF |
| `scalarMultiply` (arbitrary, wNAF) | 1.175 ms | Full-width wNAF without precomputation |
| `add(P, Q)` | 1.9 µs | Extended coordinates addition |
| `pointToBytes` | 1.5 µs | Compressed encoding (arkworks-compatible) |
| `bytesToPoint` | 1.177 ms | Decompression + subgroup check |

**Key findings:**

- **Generator multiplications** benefit heavily from noble's precomputed wNAF tables (~5x faster than GLV). GLV cannot compete here because it lacks cached tables.
- **Arbitrary-point multiplications** are where GLV dominates (~2.2x faster) thanks to the half-width scalar decomposition and Shamir's trick.
- **Point decompression** (`bytesToPoint`) is expensive (~1.2 ms) due to the modular square root and subgroup membership check. This cost appears in every VRF verification that deserializes a public key or proof point.
- **Point addition** and **serialization** are sub-microsecond and negligible in all workloads.

---

## 2. IETF VRF (Schnorr-like VRF)

IETF VRF (RFC 9381) on Bandersnatch. This is the foundational VRF primitive used by both the entropy VRF and audit signatures.

| Operation | Median | Backend |
|-----------|--------|---------|
| `IETFVRFProver.prove` | 8.199 ms | Pure TypeScript |
| `IETFVRFVerifier.verify` | 13.923 ms | Pure TypeScript |
| `IETFVRFVerifierWasm.verify` | 3.870 ms | WASM (ark-vrf-wasm) |

**Key findings:**

- **Proving** (~8 ms) is dominated by two scalar multiplications (generator + hash-to-curve point) plus the Elligator2 hash-to-curve itself.
- **Verification in Pure TS** (~14 ms) is slower than proving because it performs additional scalar multiplications for challenge recomputation plus a `bytesToPoint` decompression.
- **WASM verification** is ~3.6x faster than Pure TS, bringing verify down to ~3.9 ms. This is significant because verification happens far more frequently than proving in a validator network.

---

## 3. Pedersen VRF

The Pedersen VRF extends IETF VRF with an additional blinding factor commitment, used as the inner proof component of Ring VRF.

| Operation | Median |
|-----------|--------|
| `PedersenVRFProver.prove` | 8.776 ms |
| `PedersenVRFVerifier.verify` | 4.903 ms |

**Key findings:**

- **Proving** is ~7% slower than IETF VRF prove due to the extra blinding-base scalar multiplication.
- **Verification** (~4.9 ms) is faster than IETF TS verification because the Pedersen verifier uses the WASM backend internally.

---

## 4. Banderout and Gamma Hash (RFC 9381 Point-to-Hash)

These are lightweight hash derivations from the VRF output point (gamma). Used to extract ticket IDs, entropy, and VRF output identifiers.

| Operation | Median | Notes |
|-----------|--------|-------|
| `getBanderoutFromGamma` | 6.9 µs | First 32 bytes of `pointToHashRfc9381(gamma)` |
| `getCommitmentFromGamma` | 6.6 µs | Full 64-byte hash |
| `pointToHashRfc9381` | 3.9 µs | Raw RFC 9381 Section 5.4.2.3 hash |
| `banderout` (from 96-byte signature) | 1.238 ms | Includes `bytesToPoint` normalization |

**Key findings:**

- The raw hash operations are sub-10 µs and negligible.
- `banderout()` on a full 96-byte seal signature costs ~1.2 ms because it normalizes gamma through a full point decompression/recompression cycle (`bytesToPoint` → `pointToBytes`).

---

## 5. Entropy VRF (Gray Paper Eq. 158)

Block-level entropy generation: `H_vrfsig ∈ bssignature{H_authorbskey}{Xentropy ∥ banderout{H_sealsig}}{[]}`.

| Operation | Median | Backend |
|-----------|--------|---------|
| `generateEntropyVRFSignature` | 9.121 ms | Pure TS |
| `verifyEntropyVRFSignature` | 12.549 ms | Pure TS verifier |
| `verifyEntropyVRFSignature` | 3.369 ms | WASM verifier |

**Key findings:**

- Entropy VRF timings closely mirror raw IETF VRF timings (Section 2) with a small overhead for context construction (`Xentropy ∥ banderout{H_sealsig}`).
- **WASM verification is ~3.7x faster** than Pure TS, making it the recommended backend for block import validation.
- Every block produces exactly one entropy VRF signature and every importing node verifies it, so the per-block cost is either ~12.5 ms (Pure TS) or ~3.4 ms (WASM).

---

## 6. Audit Signatures (Gray Paper Eq. 54–62, 105)

Audit evidence generation for tranche selection. Tranche 0 uses a simple context; tranche N appends a work report hash and tranche number.

| Operation | Median | Backend |
|-----------|--------|---------|
| Tranche 0 generate | 8.068 ms | Pure TS |
| Tranche 0 verify | 11.774 ms | Pure TS |
| Tranche 0 verify | 3.300 ms | WASM |
| Tranche N generate | 8.233 ms | Pure TS |
| Tranche N verify | 12.281 ms | Pure TS |
| Tranche N verify | 3.451 ms | WASM |

**Key findings:**

- Tranche 0 and tranche N have nearly identical performance; the work report hash + tranche number concatenation adds negligible overhead (~0.2 ms) compared to the underlying VRF operations.
- **Generating** audit signatures (~8 ms) is dominated by the IETF VRF prove.
- **WASM verification** provides consistent ~3.6x speedup across both tranche types.
- In a production auditing scenario a validator may generate audit signatures for multiple tranches per block. At ~8 ms per signature, generating 10 audit signatures costs ~80 ms.

---

## 7. Announcement Signatures (Ed25519, Gray Paper Eq. 82)

Ed25519 signatures for audit announcements. These are separate from the Bandersnatch VRF audit evidence.

| Operation | Median |
|-----------|--------|
| `generateAnnouncementSignature` | 0.271 ms |
| `verifyAnnouncementSignature` | 0.966 ms |

**Key findings:**

- Ed25519 operations are **~30x faster** than Bandersnatch VRF operations, as expected for a non-VRF signature scheme on a simpler curve.
- Announcement signature verification (~1 ms) is fast enough that it does not represent a bottleneck even when processing hundreds of announcements per block.

---

## 8. Work Report Encoding (Gray Paper Appendix D)

Deterministic serialization of work reports for hashing and signing.

| Operation | Median |
|-----------|--------|
| `encodeWorkReport` | 6.6 µs |

Work report encoding is sub-10 µs and negligible relative to all cryptographic operations.

---

## 9. Blake2b Hashing

Blake2b-256 hashing at various input sizes. Used extensively for work report hashing, block header hashing, and key derivation.

| Input Size | Median |
|------------|--------|
| 32 bytes | 16.2 µs |
| 1 KB | 78.2 µs |
| 10 KB | 228.5 µs |

**Key findings:**

- Blake2b throughput is approximately 44 MB/s in Pure TypeScript (10 KB / 228.5 µs).
- For typical JAM payloads (32–256 bytes), hashing is sub-20 µs and negligible.

---

## 10. Key Derivation (JIP-5)

Full validator key derivation from a 32-byte seed: derives Ed25519, BLS12-381, and Bandersnatch key pairs via Blake2b + SHA-512 + scalar reduction.

| Operation | Median |
|-----------|--------|
| `generateDevAccountValidatorKeyPair` | 2.379 ms |

Key derivation is a one-time cost per validator session. The ~2.4 ms is dominated by the Bandersnatch scalar multiplication for public key generation.

---

## Cross-Component Performance Summary

Sorted by median execution time (slowest first):

| Operation | Median | Gray Paper Reference |
|-----------|--------|---------------------|
| IETF VRF verify (Pure TS) | 13.923 ms | bandersnatch.tex Eq. 8 |
| Entropy VRF verify (Pure TS) | 12.549 ms | safrole.tex Eq. 158 |
| Audit sig verify TN (Pure TS) | 12.281 ms | auditing.tex Eq. 105 |
| Audit sig verify T0 (Pure TS) | 11.774 ms | auditing.tex Eq. 54–62 |
| Entropy VRF sign | 9.121 ms | safrole.tex Eq. 158 |
| Pedersen VRF prove | 8.776 ms | bandersnatch.tex Eq. 12 |
| Audit sig gen (tranche N) | 8.233 ms | auditing.tex Eq. 105 |
| IETF VRF prove | 8.199 ms | bandersnatch.tex Eq. 8 |
| Audit sig gen (tranche 0) | 8.068 ms | auditing.tex Eq. 54–62 |
| Pedersen VRF verify | 4.903 ms | bandersnatch.tex Eq. 12 |
| IETF VRF verify (WASM) | 3.870 ms | bandersnatch.tex Eq. 8 |
| Audit sig verify TN (WASM) | 3.451 ms | auditing.tex Eq. 105 |
| Entropy VRF verify (WASM) | 3.369 ms | safrole.tex Eq. 158 |
| Audit sig verify T0 (WASM) | 3.300 ms | auditing.tex Eq. 54–62 |
| Key derivation (JIP-5) | 2.379 ms | — |
| banderout (from seal sig) | 1.238 ms | bandersnatch.tex Eq. 8 |
| bytesToPoint | 1.177 ms | — |
| Announcement sig verify | 0.966 ms | auditing.tex Eq. 82 |
| scalarMultiply (arb, GLV) | 0.540 ms | — |
| Announcement sig gen | 0.271 ms | auditing.tex Eq. 82 |
| scalarMultiply (gen, wNAF) | 0.111 ms | — |
| blake2bHash (10 KB) | 228.5 µs | — |
| blake2bHash (1 KB) | 78.2 µs | — |
| blake2bHash (32 B) | 16.2 µs | — |
| encodeWorkReport | 6.6 µs | Appendix D Eq. 231–240 |
| getBanderoutFromGamma | 6.9 µs | bandersnatch.tex Eq. 8 |
| pointToHashRfc9381 | 3.9 µs | RFC 9381 §5.4.2.3 |
| point add | 1.9 µs | — |
| pointToBytes | 1.5 µs | — |

**Bottleneck analysis:**

1. **VRF verification** (11–14 ms Pure TS, 3.3–3.9 ms WASM) is the single most expensive per-invocation operation. A block import touching multiple VRF proofs accumulates this cost linearly.
2. **VRF proving** (~8–9 ms) is the dominant cost for block authors and auditors. Generating audit evidence for 10 tranches costs ~80 ms.
3. **Point decompression** (`bytesToPoint` at ~1.2 ms) is a hidden cost embedded in every verification and `banderout` extraction.
4. **Ed25519** and **Blake2b** operations are 10–100x cheaper than Bandersnatch VRF operations and do not represent bottlenecks.
5. **Codec** operations (work report encoding) are negligible at ~7 µs.

**Recommendation:** For production validators, use the WASM verifier backend for all VRF verification paths (entropy, audit, IETF) to achieve a consistent ~3.5x speedup. Pure TypeScript proving is acceptable since proving is less frequent than verification. For maximum throughput, the W3F native backend (see Ring VRF section above) provides an additional ~10–20x improvement over WASM for Ring VRF operations.
