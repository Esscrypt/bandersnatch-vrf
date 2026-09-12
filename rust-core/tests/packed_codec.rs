use pbnjam_ring_proof_core::packed::{
    decode_bvrf_batch_verify_items, decode_bvrf_ietf_verify_request, decode_bvrf_last_error,
    decode_bvrf_ring_prepare_output, decode_bvrf_ring_prepare_request, decode_bvrf_srs_open_output,
    decode_bvrf_srs_open_request, decode_bvrf_validity, encode_bvrf_batch_verify_items,
    encode_bvrf_ietf_verify_request, encode_bvrf_last_error, encode_bvrf_ring_prepare_output,
    encode_bvrf_ring_prepare_request, encode_bvrf_srs_open_output, encode_bvrf_srs_open_request,
    encode_bvrf_validity, BvrfBatchVerifyItem, BvrfIetfVerifyRequest, CodecError,
};
use std::path::PathBuf;

fn packed_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../pvm-rust/core/testdata/packed")
}

fn read_fixture(name: &str) -> Vec<u8> {
    std::fs::read(packed_dir().join(name)).unwrap_or_else(|err| {
        panic!("missing packed fixture {name}: {err}");
    })
}

#[test]
fn packed_srs_open_matches_fixture() {
    let encoded = encode_bvrf_srs_open_request("srs.bin");
    assert_eq!(encoded, read_fixture("bvrf-srs-open.bin"));
    let decoded = decode_bvrf_srs_open_request(&encoded).expect("srs path");
    assert_eq!(decoded, "srs.bin");
}

#[test]
fn packed_srs_open_output_matches_fixture() {
    let encoded = encode_bvrf_srs_open_output(7);
    assert_eq!(encoded, read_fixture("bvrf-srs-open-output.bin"));
    let decoded = decode_bvrf_srs_open_output(&encoded).expect("srs handle");
    assert_eq!(decoded, 7);
}

#[test]
fn packed_ring_prepare_request_matches_fixture() {
    let mut ring_keys = vec![0x11u8; 32];
    ring_keys.extend(std::iter::repeat(0x22u8).take(32));
    let encoded = encode_bvrf_ring_prepare_request(&ring_keys);
    assert_eq!(encoded, read_fixture("bvrf-ring-keys.bin"));
    let decoded = decode_bvrf_ring_prepare_request(&encoded).expect("ring keys");
    assert_eq!(decoded, ring_keys);
}

#[test]
fn packed_ring_prepare_output_matches_fixture() {
    let commitment = vec![0xabu8; 144];
    let encoded = encode_bvrf_ring_prepare_output(5, &commitment).expect("144-byte commitment");
    assert_eq!(encoded, read_fixture("bvrf-ring-prepare-output.bin"));
    let decoded = decode_bvrf_ring_prepare_output(&encoded).expect("ring prepare");
    assert_eq!(decoded.handle, 5);
    assert_eq!(decoded.commitment, commitment);
}

#[test]
fn packed_batch_verify_items_match_fixture() {
    let items = [BvrfBatchVerifyItem {
        proof: vec![0xde, 0xad],
        key_commitment: vec![0xccu8; 32],
    }];
    let encoded = encode_bvrf_batch_verify_items(&items).expect("32-byte key commitment");
    assert_eq!(encoded, read_fixture("bvrf-batch-verify-items.bin"));
    let decoded = decode_bvrf_batch_verify_items(&encoded).expect("batch items");
    assert_eq!(decoded, items);
}

#[test]
fn packed_ietf_verify_request_matches_fixture() {
    let request = BvrfIetfVerifyRequest {
        public_key: vec![1],
        input: vec![2, 3],
        proof: vec![4],
        aux: vec![],
    };
    let encoded = encode_bvrf_ietf_verify_request(&request);
    assert_eq!(encoded, read_fixture("bvrf-ietf-verify.bin"));
    let decoded = decode_bvrf_ietf_verify_request(&encoded).expect("ietf request");
    assert_eq!(decoded, request);
}

#[test]
fn packed_validity_byte_matches_fixture() {
    let encoded = encode_bvrf_validity(true);
    assert_eq!(encoded, read_fixture("bvrf-validity.bin"));
    assert!(decode_bvrf_validity(&encoded).expect("validity"));
}

#[test]
fn packed_last_error_matches_fixture() {
    let encoded = encode_bvrf_last_error("boom");
    assert_eq!(encoded, read_fixture("bvrf-last-error.bin"));
    let decoded = decode_bvrf_last_error(&encoded).expect("last error");
    assert_eq!(decoded, "boom");
}

#[test]
fn packed_decode_rejects_format_version_mismatch() {
    let err = decode_bvrf_srs_open_request(&[2]).expect_err("version mismatch");
    match err {
        CodecError::Malformed(message) => {
            assert!(
                message.contains("format version"),
                "unexpected message: {message}"
            );
        }
    }
}

fn assert_malformed(err: CodecError) {
    match err {
        CodecError::Malformed(message) => {
            assert!(
                message.contains("malformed"),
                "unexpected message: {message}"
            );
        }
    }
}

#[test]
fn packed_encode_rejects_short_and_long_ring_commitment() {
    let short = encode_bvrf_ring_prepare_output(5, &[0u8; 143]).expect_err("short commitment");
    assert_malformed(short);
    let long = encode_bvrf_ring_prepare_output(5, &[0u8; 145]).expect_err("long commitment");
    assert_malformed(long);
}

#[test]
fn packed_encode_rejects_short_and_long_batch_key_commitment() {
    let short_item = BvrfBatchVerifyItem {
        proof: vec![0xde, 0xad],
        key_commitment: vec![0xccu8; 31],
    };
    let long_item = BvrfBatchVerifyItem {
        proof: vec![0xde, 0xad],
        key_commitment: vec![0xccu8; 33],
    };
    let short = encode_bvrf_batch_verify_items(&[short_item]).expect_err("short key commitment");
    assert_malformed(short);
    let long = encode_bvrf_batch_verify_items(&[long_item]).expect_err("long key commitment");
    assert_malformed(long);
}
