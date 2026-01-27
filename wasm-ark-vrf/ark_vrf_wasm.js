
let imports = {};
imports['__wbindgen_placeholder__'] = module.exports;

let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

function decodeText(ptr, len) {
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let WASM_VECTOR_LEN = 0;

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    }
}

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedDataViewMemory0 = null;

function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

exports.init = function() {
    wasm.init();
};

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}
/**
 * Verify a ring proof using ark-vrf.
 *
 * # Arguments
 * * `srs_bytes` - Serialized PCS params (SRS) bytes (uncompressed arkworks format)
 * * `proof_bytes` - Serialized RingProof
 * * `ring_keys_bytes` - Serialized ring public keys (compressed, 32 bytes each)
 * * `key_commitment_bytes` - Serialized key commitment (Y_bar from Pedersen proof, compressed, 32 bytes)
 * * `ring_size` - Number of keys in the ring
 *
 * # Returns
 * * `true` if proof is valid, `false` otherwise
 * @param {Uint8Array} srs_bytes
 * @param {Uint8Array} proof_bytes
 * @param {Uint8Array} ring_keys_bytes
 * @param {Uint8Array} key_commitment_bytes
 * @param {number} ring_size
 * @returns {boolean}
 */
exports.verify_ring_proof = function(srs_bytes, proof_bytes, ring_keys_bytes, key_commitment_bytes, ring_size) {
    const ptr0 = passArray8ToWasm0(srs_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(proof_bytes, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(ring_keys_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(key_commitment_bytes, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.verify_ring_proof(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ring_size);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
};

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}
/**
 * Compute ring commitment (FixedColumnsCommitted) from ring keys.
 * This matches ark-vrf's RingProofParams::verifier_key().commitment() functionality.
 *
 * # Arguments
 * * `srs_bytes` - Serialized PCS params (SRS) bytes (uncompressed arkworks format)
 * * `ring_keys_bytes` - Serialized ring public keys (compressed, 32 bytes each)
 * * `ring_size` - Number of keys in the ring
 *
 * # Returns
 * * Serialized FixedColumnsCommitted (144 bytes: cx, cy, selector, each 48 bytes)
 * @param {Uint8Array} srs_bytes
 * @param {Uint8Array} ring_keys_bytes
 * @param {number} ring_size
 * @returns {Uint8Array}
 */
exports.compute_ring_commitment = function(srs_bytes, ring_keys_bytes, ring_size) {
    const ptr0 = passArray8ToWasm0(srs_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(ring_keys_bytes, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.compute_ring_commitment(ptr0, len0, ptr1, len1, ring_size);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
};

/**
 * Generate a ring proof using ark-vrf (matches test vectors exactly).
 *
 * This function uses ark-vrf's RingProver which matches the exact implementation
 * used to generate the test vectors.
 *
 * # Arguments
 * * `srs_bytes` - Serialized PCS params (SRS) bytes (uncompressed arkworks format)
 * * `ring_keys_bytes` - Serialized ring public keys (compressed, 32 bytes each)
 * * `blinding_factor_bytes` - Serialized blinding factor (32 bytes, Fr scalar)
 * * `prover_index` - Index of the prover's key in the ring (0-based)
 * * `ring_size` - Number of keys in the ring
 *
 * # Returns
 * * Serialized RingProof (matches test vectors exactly)
 * @param {Uint8Array} srs_bytes
 * @param {Uint8Array} ring_keys_bytes
 * @param {Uint8Array} blinding_factor_bytes
 * @param {number} prover_index
 * @param {number} ring_size
 * @returns {Uint8Array}
 */
exports.prove_ring_proof = function(srs_bytes, ring_keys_bytes, blinding_factor_bytes, prover_index, ring_size) {
    const ptr0 = passArray8ToWasm0(srs_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(ring_keys_bytes, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(blinding_factor_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.prove_ring_proof(ptr0, len0, ptr1, len1, ptr2, len2, prover_index, ring_size);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
};

exports.__wbg___wbindgen_throw_b855445ff6a94295 = function(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
};

exports.__wbg_error_7534b8e9a36f1ab4 = function(arg0, arg1) {
    let deferred0_0;
    let deferred0_1;
    try {
        deferred0_0 = arg0;
        deferred0_1 = arg1;
        console.error(getStringFromWasm0(arg0, arg1));
    } finally {
        wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
    }
};

exports.__wbg_new_8a6f238a6ece86ea = function() {
    const ret = new Error();
    return ret;
};

exports.__wbg_stack_0ed75d68575b0f3c = function(arg0, arg1) {
    const ret = arg1.stack;
    const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
    getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
};

exports.__wbindgen_cast_2241b6af4c4b2941 = function(arg0, arg1) {
    // Cast intrinsic for `Ref(String) -> Externref`.
    const ret = getStringFromWasm0(arg0, arg1);
    return ret;
};

exports.__wbindgen_init_externref_table = function() {
    const table = wasm.__wbindgen_externrefs;
    const offset = table.grow(4);
    table.set(0, undefined);
    table.set(offset + 0, undefined);
    table.set(offset + 1, null);
    table.set(offset + 2, true);
    table.set(offset + 3, false);
    ;
};

const wasmPath = `${__dirname}/ark_vrf_wasm_bg.wasm`;
const wasmBytes = require('fs').readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);
const wasm = exports.__wasm = new WebAssembly.Instance(wasmModule, imports).exports;

wasm.__wbindgen_start();

