# ark-vrf-wasm

WASM bindings for ark-vrf (ring proof and IETF VRF).

## Prerequisites

1. **Rust wasm target** (required once):

   ```bash
   rustup target add wasm32-unknown-unknown
   ```

2. **Full JS + WASM bundle** (optional): install [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/):

   ```bash
   cargo install wasm-pack
   ```

## Build to WASM (raw binary)

From this directory or the ark-vrf repo root:

```bash
cd submodules/ark-vrf/ark-vrf-wasm
cargo build --release --target wasm32-unknown-unknown
```

Output: `target/wasm32-unknown-unknown/release/ark_vrf_wasm.wasm` (no JS glue).

## Build full package (WASM + JS + types) with wasm-pack

From this directory:

```bash
wasm-pack build --release --target nodejs --out-dir pkg
```

This produces `pkg/ark_vrf_wasm.js`, `pkg/ark_vrf_wasm_bg.wasm`, and `pkg/ark_vrf_wasm.d.ts`. To update the bandersnatch-vrf package’s pre-built WASM, copy the contents of `pkg/` into `packages/bandersnatch-vrf/wasm-ark-vrf/` (the package keeps a hand-maintained `ark_vrf_wasm.d.ts`; merge or replace as needed).

**Web target** (browser):

```bash
wasm-pack build --release --target web --out-dir pkg
```
