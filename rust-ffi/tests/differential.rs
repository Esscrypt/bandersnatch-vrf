//! Differential tests: Node-API core vs Bandersnatch C ABI.
//!
//! napi `verify_ietf_vrf` / `batch_verify_ring_vrf` wrap
//! `pbnjam_ring_proof_core`. These tests call that core and the C ABI on the
//! same IETF/ring vectors and require identical validity. Invalid proofs must
//! return status 0 with a false byte, not an evaluation failure.

use pbnjam_bvrf_ffi::{
    pbnjam_bvrf_ietf_verify, pbnjam_bvrf_ring_batch_verify, pbnjam_bvrf_ring_prepare,
    pbnjam_bvrf_ring_release, pbnjam_bvrf_srs_open, pbnjam_bvrf_srs_release,
};
use pbnjam_ring_proof_core::packed::{
    decode_bvrf_ring_prepare_output, decode_bvrf_srs_open_output, decode_bvrf_validity,
    encode_bvrf_batch_verify_items, encode_bvrf_ietf_verify_request,
    encode_bvrf_ring_prepare_request, encode_bvrf_srs_open_request, BvrfBatchVerifyItem,
    BvrfIetfVerifyRequest,
};
use pbnjam_ring_proof_core::{
    batch_verify_ring_vrf, compute_ring_commitment, compute_ring_verifier_key, verify_ietf_vrf,
    RingBatchItemBytes,
};
use std::os::raw::c_void;
use std::path::PathBuf;

struct Capture {
    data: Vec<u8>,
    calls: usize,
}

extern "C" fn capture_cb(data: *const u8, len: usize, ctx: *mut c_void) {
    let capture = unsafe { &mut *(ctx as *mut Capture) };
    capture.calls += 1;
    if data.is_null() {
        capture.data.clear();
        return;
    }
    capture.data = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return Vec::new();
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../src/__tests__/vectors")
}

fn srs_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-data/srs/zcash-srs-2-11-uncompressed.bin")
}

fn load_json(name: &str) -> serde_json::Value {
    let path = vectors_dir().join(name);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("missing vector file {}: {err}", path.display());
    });
    serde_json::from_str(&raw).expect("vector json")
}

fn ietf_proof_bytes(vector: &serde_json::Value) -> Vec<u8> {
    let mut proof = hex_to_bytes(vector["gamma"].as_str().expect("gamma"));
    proof.extend_from_slice(&hex_to_bytes(vector["proof_c"].as_str().expect("proof_c")));
    proof.extend_from_slice(&hex_to_bytes(vector["proof_s"].as_str().expect("proof_s")));
    proof
}

fn c_abi_ietf_verify(public_key: &[u8], input: &[u8], proof: &[u8], aux: &[u8]) -> (i32, Option<bool>) {
    let req = encode_bvrf_ietf_verify_request(&BvrfIetfVerifyRequest {
        public_key: public_key.to_vec(),
        input: input.to_vec(),
        proof: proof.to_vec(),
        aux: aux.to_vec(),
    });
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = pbnjam_bvrf_ietf_verify(
        req.as_ptr(),
        req.len(),
        Some(capture_cb),
        &mut capture as *mut Capture as *mut c_void,
    );
    if status != 0 {
        return (status, None);
    }
    assert_eq!(capture.calls, 1);
    (
        status,
        Some(decode_bvrf_validity(&capture.data).expect("packed validity")),
    )
}

#[test]
fn differential_ietf_vectors_match_napi_core_and_c_abi() {
    let vectors = load_json("bandersnatch_sha-512_ell2_ietf.json");
    let rows = vectors.as_array().expect("ietf vector array");
    assert!(!rows.is_empty(), "IETF vectors must be present");

    for (index, vector) in rows.iter().enumerate() {
        let public_key = hex_to_bytes(vector["pk"].as_str().expect("pk"));
        let input = hex_to_bytes(vector["alpha"].as_str().unwrap_or(""));
        let aux = hex_to_bytes(vector["ad"].as_str().unwrap_or(""));
        let proof = ietf_proof_bytes(vector);

        let napi = verify_ietf_vrf(&public_key, &input, &proof, &aux).expect("napi core verify");
        let (status, c_abi) = c_abi_ietf_verify(&public_key, &input, &proof, &aux);
        assert_eq!(status, 0, "ietf vector {index} C ABI status");
        assert_eq!(c_abi, Some(true), "ietf vector {index} C ABI validity");
        assert_eq!(napi, true, "ietf vector {index} napi core validity");
        assert_eq!(napi, c_abi.unwrap());
    }
}

#[test]
fn differential_ietf_invalid_proof_is_status_zero_false_on_both_paths() {
    let vectors = load_json("bandersnatch_sha-512_ell2_ietf.json");
    let rows = vectors.as_array().expect("ietf vector array");
    let valid = &rows[0];
    let other = &rows[1];
    let public_key = hex_to_bytes(valid["pk"].as_str().expect("pk"));
    let input = hex_to_bytes(valid["alpha"].as_str().unwrap_or(""));
    let aux = hex_to_bytes(valid["ad"].as_str().unwrap_or(""));
    let mut proof = ietf_proof_bytes(valid);
    let other_s = hex_to_bytes(other["proof_s"].as_str().expect("proof_s"));
    proof.splice(64..96, other_s);

    let napi = verify_ietf_vrf(&public_key, &input, &proof, &aux).expect("napi core verify");
    let (status, c_abi) = c_abi_ietf_verify(&public_key, &input, &proof, &aux);
    assert_eq!(status, 0, "invalid IETF proof must stay status 0");
    assert_eq!(c_abi, Some(false));
    assert_eq!(napi, false);
}

struct PreparedRing {
    srs_handle: u32,
    ring_handle: u32,
    commitment: Vec<u8>,
}

impl Drop for PreparedRing {
    fn drop(&mut self) {
        let _ = pbnjam_bvrf_ring_release(self.ring_handle);
        let _ = pbnjam_bvrf_srs_release(self.srs_handle);
    }
}

fn c_abi_prepare_ring(ring_keys: &[u8]) -> PreparedRing {
    let path = srs_fixture_path();
    let req = encode_bvrf_srs_open_request(path.to_str().expect("utf-8 srs path"));
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = pbnjam_bvrf_srs_open(
        req.as_ptr(),
        req.len(),
        Some(capture_cb),
        &mut capture as *mut Capture as *mut c_void,
    );
    assert_eq!(status, 0, "srs open");
    let srs_handle = decode_bvrf_srs_open_output(&capture.data).expect("srs handle");

    let prepare_req = encode_bvrf_ring_prepare_request(ring_keys);
    let mut prepare_capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let prepare_status = pbnjam_bvrf_ring_prepare(
        srs_handle,
        prepare_req.as_ptr(),
        prepare_req.len(),
        Some(capture_cb),
        &mut prepare_capture as *mut Capture as *mut c_void,
    );
    assert_eq!(prepare_status, 0, "ring prepare");
    let prepared = decode_bvrf_ring_prepare_output(&prepare_capture.data).expect("prepare output");
    PreparedRing {
        srs_handle,
        ring_handle: prepared.handle,
        commitment: prepared.commitment,
    }
}

fn c_abi_batch_verify(
    ring_handle: u32,
    ring_size: u32,
    proof: &[u8],
    key_commitment: &[u8],
) -> (i32, Option<bool>) {
    let req = encode_bvrf_batch_verify_items(&[BvrfBatchVerifyItem {
        proof: proof.to_vec(),
        key_commitment: key_commitment.to_vec(),
    }])
    .expect("encode batch items");
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = pbnjam_bvrf_ring_batch_verify(
        ring_handle,
        ring_size,
        req.as_ptr(),
        req.len(),
        Some(capture_cb),
        &mut capture as *mut Capture as *mut c_void,
    );
    if status != 0 {
        return (status, None);
    }
    (
        status,
        Some(decode_bvrf_validity(&capture.data).expect("packed validity")),
    )
}

#[test]
fn differential_ring_vectors_match_napi_core_and_c_abi() {
    let srs = std::fs::read(srs_fixture_path()).expect("real SRS fixture");
    let vectors = load_json("bandersnatch_sha-512_ell2_ring.json");
    let rows = vectors.as_array().expect("ring vector array");
    assert!(rows.len() >= 2, "need at least two ring vectors");

    for (index, vector) in rows.iter().take(2).enumerate() {
        let ring_keys = hex_to_bytes(vector["ring_pks"].as_str().expect("ring_pks"));
        let proof = hex_to_bytes(vector["ring_proof"].as_str().expect("ring_proof"));
        let key_commitment = hex_to_bytes(vector["proof_pk_com"].as_str().expect("proof_pk_com"));
        let ring_size = (ring_keys.len() / 32) as u32;

        let napi_commitment = compute_ring_commitment(&srs, &ring_keys).expect("napi commitment");
        let napi_vk = compute_ring_verifier_key(&srs, &ring_keys).expect("napi verifier key");
        let napi_valid = batch_verify_ring_vrf(
            &napi_vk,
            ring_size,
            &[RingBatchItemBytes {
                proof_bytes: proof.clone(),
                key_commitment_bytes: key_commitment.clone(),
            }],
        )
        .expect("napi batch verify");

        let prepared = c_abi_prepare_ring(&ring_keys);
        assert_eq!(
            prepared.commitment, napi_commitment,
            "ring vector {index} commitment"
        );
        let (status, c_abi_valid) =
            c_abi_batch_verify(prepared.ring_handle, ring_size, &proof, &key_commitment);
        assert_eq!(status, 0, "ring vector {index} C ABI status");
        assert_eq!(c_abi_valid, Some(true), "ring vector {index} C ABI validity");
        assert_eq!(napi_valid, true, "ring vector {index} napi validity");
        assert_eq!(napi_valid, c_abi_valid.unwrap());
    }
}

#[test]
fn differential_ring_invalid_proof_is_status_zero_false_on_both_paths() {
    let srs = std::fs::read(srs_fixture_path()).expect("real SRS fixture");
    let vectors = load_json("bandersnatch_sha-512_ell2_ring.json");
    let rows = vectors.as_array().expect("ring vector array");
    assert!(rows.len() >= 2, "need at least two ring vectors");
    // Keep a deserializable proof shape (same pattern as the IETF invalid case):
    // verify vector[0]'s ring against vector[1]'s proof and key commitment.
    let ring_keys = hex_to_bytes(rows[0]["ring_pks"].as_str().expect("ring_pks"));
    let proof = hex_to_bytes(rows[1]["ring_proof"].as_str().expect("ring_proof"));
    let key_commitment = hex_to_bytes(rows[1]["proof_pk_com"].as_str().expect("proof_pk_com"));
    let ring_size = (ring_keys.len() / 32) as u32;

    let napi_vk = compute_ring_verifier_key(&srs, &ring_keys).expect("napi verifier key");
    let napi_valid = batch_verify_ring_vrf(
        &napi_vk,
        ring_size,
        &[RingBatchItemBytes {
            proof_bytes: proof.clone(),
            key_commitment_bytes: key_commitment.clone(),
        }],
    )
    .expect("napi batch verify of mismatched ring proof");

    let prepared = c_abi_prepare_ring(&ring_keys);
    let (status, c_abi_valid) =
        c_abi_batch_verify(prepared.ring_handle, ring_size, &proof, &key_commitment);
    assert_eq!(status, 0, "invalid ring proof must stay status 0");
    assert_eq!(c_abi_valid, Some(false));
    assert_eq!(napi_valid, false);
}
