//! C ABI tests for `pbnjam-bvrf-ffi`.
//!
//! Production change that would fail these tests: dropping generation on
//! release so a second `srs_release` returns 0, or letting a panic unwind
//! instead of becoming status 5 with a drained last-error message.

use pbnjam_bvrf_ffi::{
    pbnjam_bvrf_abi_version, pbnjam_bvrf_ietf_verify, pbnjam_bvrf_ring_batch_verify,
    pbnjam_bvrf_ring_prepare, pbnjam_bvrf_ring_release, pbnjam_bvrf_srs_open,
    pbnjam_bvrf_srs_release, pbnjam_bvrf_take_last_error, EXPORTED_SYMBOLS,
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

fn encode_srs_open_request(path: &str) -> Vec<u8> {
    let path_bytes = path.as_bytes();
    let mut buf = vec![0x01];
    buf.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(path_bytes);
    buf
}

fn decode_u32_handle(bytes: &[u8]) -> u32 {
    assert!(bytes.len() >= 5, "packed handle payload too short");
    assert_eq!(bytes[0], 0x01);
    u32::from_le_bytes(bytes[1..5].try_into().expect("handle bytes"))
}

fn decode_last_error(bytes: &[u8]) -> String {
    assert!(bytes.len() >= 5, "packed last-error payload too short");
    assert_eq!(bytes[0], 0x01);
    let len = u32::from_le_bytes(bytes[1..5].try_into().expect("len bytes")) as usize;
    String::from_utf8(bytes[5..5 + len].to_vec()).expect("utf-8 last error")
}

fn decode_validity(bytes: &[u8]) -> u8 {
    assert_eq!(bytes.len(), 2);
    assert_eq!(bytes[0], 0x01);
    bytes[1]
}

fn take_last_error_string() -> String {
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = {
        pbnjam_bvrf_take_last_error(Some(capture_cb), &mut capture as *mut Capture as *mut c_void)
    };
    assert_eq!(status, 0);
    assert_eq!(capture.calls, 1);
    decode_last_error(&capture.data)
}

fn srs_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-data/srs/zcash-srs-2-11-uncompressed.bin")
}

fn open_test_handle() -> u32 {
    let path = srs_fixture_path();
    let req = encode_srs_open_request(path.to_str().expect("utf-8 srs path"));
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = {
        pbnjam_bvrf_srs_open(
            req.as_ptr(),
            req.len(),
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        )
    };
    if status != 0 {
        panic!("srs open for test handle failed with {status}: {}", take_last_error_string());
    }
    assert_eq!(capture.calls, 1);
    decode_u32_handle(&capture.data)
}

#[test]
fn released_handle_is_stale() {
    let handle = open_test_handle();
    assert_eq!(pbnjam_bvrf_srs_release(handle), 0);
    assert_eq!(pbnjam_bvrf_srs_release(handle), 3);
}

#[test]
fn abi_version_is_one() {
    assert_eq!(pbnjam_bvrf_abi_version(), 1);
}

#[test]
fn malformed_srs_open_request_is_status_one() {
    let req = [0x02u8];
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = {
        pbnjam_bvrf_srs_open(
            req.as_ptr(),
            req.len(),
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        )
    };
    assert_eq!(status, 1);
    assert_eq!(capture.calls, 0);
    assert!(!take_last_error_string().is_empty());
}

#[test]
fn missing_srs_file_is_status_four() {
    let req = encode_srs_open_request("/no/such/pbnjam-bvrf-srs.bin");
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = {
        pbnjam_bvrf_srs_open(
            req.as_ptr(),
            req.len(),
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        )
    };
    assert_eq!(status, 4);
    assert_eq!(capture.calls, 0);
    assert!(!take_last_error_string().is_empty());
}

#[test]
fn unparseable_srs_file_is_status_four() {
    let dir = std::env::temp_dir();
    let path = dir.join("pbnjam-bvrf-garbage-srs.bin");
    std::fs::write(&path, b"not-an-srs").expect("write garbage srs");
    let req = encode_srs_open_request(path.to_str().expect("utf-8 path"));
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = {
        pbnjam_bvrf_srs_open(
            req.as_ptr(),
            req.len(),
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        )
    };
    let _ = std::fs::remove_file(&path);
    assert_eq!(status, 4);
    assert_eq!(capture.calls, 0);
    assert!(!take_last_error_string().is_empty());
}

#[test]
fn unknown_handle_is_status_three() {
    assert_eq!(pbnjam_bvrf_srs_release(0), 3);
    assert_eq!(pbnjam_bvrf_ring_release(0), 3);
}

#[test]
fn srs_handle_cannot_be_used_as_ring_handle() {
    let srs_handle = open_test_handle();
    assert_eq!(pbnjam_bvrf_ring_release(srs_handle), 3);
    let req = {
        let mut buf = vec![0x01];
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf
    };
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = {
        pbnjam_bvrf_ring_batch_verify(
            srs_handle,
            8,
            req.as_ptr(),
            req.len(),
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        )
    };
    assert_eq!(status, 3);
    assert_eq!(pbnjam_bvrf_srs_release(srs_handle), 0);
}

fn encode_ietf_verify_request(public_key: &[u8], input: &[u8], proof: &[u8], aux: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x01];
    for blob in [public_key, input, proof, aux] {
        buf.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        buf.extend_from_slice(blob);
    }
    buf
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn ietf_valid_proof_is_status_zero_with_true_byte() {
    let public_key = hex_to_bytes("a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b");
    let gamma = hex_to_bytes("e7aa5154103450f0a0525a36a441f827296ee489ef30ed8787cff8df1bef223f");
    let proof_c = hex_to_bytes("439fd9495643314fa623f2581f4b3d7d6037394468084f4ad7d8031479d9d101");
    let proof_s = hex_to_bytes("828bedd2ad95380b11f67a05ea0a76f0c3fef2bee9f043f4dffdddde09f55c01");
    let mut proof = gamma;
    proof.extend_from_slice(&proof_c);
    proof.extend_from_slice(&proof_s);
    let req = encode_ietf_verify_request(&public_key, &[], &proof, &[]);
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = {
        pbnjam_bvrf_ietf_verify(
            req.as_ptr(),
            req.len(),
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        )
    };
    assert_eq!(status, 0);
    assert_eq!(capture.calls, 1);
    assert_eq!(decode_validity(&capture.data), 1);
}

#[test]
fn ietf_invalid_proof_is_status_zero_with_false_byte() {
    let public_key = hex_to_bytes("a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b");
    let gamma = hex_to_bytes("e7aa5154103450f0a0525a36a441f827296ee489ef30ed8787cff8df1bef223f");
    let proof_c = hex_to_bytes("439fd9495643314fa623f2581f4b3d7d6037394468084f4ad7d8031479d9d101");
    let proof_s = hex_to_bytes("18c74ffd67e6abc658e2d05ecd3101ddc0c33623823f2395538cf8d39e654f12");
    let mut proof = gamma;
    proof.extend_from_slice(&proof_c);
    proof.extend_from_slice(&proof_s);
    let req = encode_ietf_verify_request(&public_key, &[], &proof, &[]);
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = {
        pbnjam_bvrf_ietf_verify(
            req.as_ptr(),
            req.len(),
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        )
    };
    assert_eq!(status, 0);
    assert_eq!(capture.calls, 1);
    assert_eq!(decode_validity(&capture.data), 0);
}

#[test]
fn ietf_short_proof_is_evaluation_failure() {
    let public_key = [0u8; 32];
    let req = encode_ietf_verify_request(&public_key, &[], &[0u8; 8], &[]);
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = {
        pbnjam_bvrf_ietf_verify(
            req.as_ptr(),
            req.len(),
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        )
    };
    assert_eq!(status, 4);
    assert_eq!(capture.calls, 0);
    assert!(!take_last_error_string().is_empty());
}

#[test]
fn ring_prepare_unknown_srs_handle_is_status_three() {
    let req = {
        let mut buf = vec![0x01];
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf
    };
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = {
        pbnjam_bvrf_ring_prepare(
            0,
            req.as_ptr(),
            req.len(),
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        )
    };
    assert_eq!(status, 3);
    assert_eq!(capture.calls, 0);
}

#[test]
fn ring_prepare_malformed_request_is_status_one() {
    let srs_handle = open_test_handle();
    let req = [0x02u8];
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = {
        pbnjam_bvrf_ring_prepare(
            srs_handle,
            req.as_ptr(),
            req.len(),
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        )
    };
    assert_eq!(pbnjam_bvrf_srs_release(srs_handle), 0);
    assert_eq!(status, 1);
    assert_eq!(capture.calls, 0);
}

#[test]
fn ring_prepare_odd_keys_length_is_status_two() {
    let srs_handle = open_test_handle();
    let mut req = vec![0x01];
    req.extend_from_slice(&1u32.to_le_bytes());
    req.push(0xff);
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = {
        pbnjam_bvrf_ring_prepare(
            srs_handle,
            req.as_ptr(),
            req.len(),
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        )
    };
    assert_eq!(pbnjam_bvrf_srs_release(srs_handle), 0);
    assert_eq!(status, 2);
    assert_eq!(capture.calls, 0);
}

#[test]
fn batch_verify_unknown_ring_handle_is_status_three() {
    let req = {
        let mut buf = vec![0x01];
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf
    };
    let mut capture = Capture {
        data: Vec::new(),
        calls: 0,
    };
    let status = {
        pbnjam_bvrf_ring_batch_verify(
            1,
            8,
            req.as_ptr(),
            req.len(),
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        )
    };
    assert_eq!(status, 3);
    assert_eq!(capture.calls, 0);
}

#[test]
fn ffi_json_matches_no_mangle_exports() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ffi.json"))
        .expect("ffi.json emitted by build.rs");
    let (abi_version, mut json_names) = parse_ffi_json_symbol_names(&manifest);
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/abi.rs"));
    let mut no_mangle_names = no_mangle_fn_names(src);
    json_names.sort();
    no_mangle_names.sort();
    assert_eq!(abi_version, 1);
    assert_eq!(
        json_names, no_mangle_names,
        "ffi.json symbols must match #[no_mangle] exports in src/abi.rs"
    );
    let mut source_names: Vec<String> = EXPORTED_SYMBOLS
        .iter()
        .map(|symbol| symbol.name.to_string())
        .collect();
    source_names.sort();
    assert_eq!(
        json_names, source_names,
        "ffi.json symbols must match EXPORTED_SYMBOLS"
    );
    assert!(!json_names.iter().any(|name| name.contains("prove")));
    assert!(!json_names.iter().any(|name| name.contains("force_panic")));
    assert!(!json_names.iter().any(|name| name.contains("pedersen")));

    let linked: &[(&str, *const ())] = &[
        ("pbnjam_bvrf_abi_version", pbnjam_bvrf_abi_version as *const ()),
        ("pbnjam_bvrf_ietf_verify", pbnjam_bvrf_ietf_verify as *const ()),
        (
            "pbnjam_bvrf_ring_batch_verify",
            pbnjam_bvrf_ring_batch_verify as *const (),
        ),
        ("pbnjam_bvrf_ring_prepare", pbnjam_bvrf_ring_prepare as *const ()),
        ("pbnjam_bvrf_ring_release", pbnjam_bvrf_ring_release as *const ()),
        ("pbnjam_bvrf_srs_open", pbnjam_bvrf_srs_open as *const ()),
        ("pbnjam_bvrf_srs_release", pbnjam_bvrf_srs_release as *const ()),
        (
            "pbnjam_bvrf_take_last_error",
            pbnjam_bvrf_take_last_error as *const (),
        ),
    ];
    let mut linked_names: Vec<String> = linked.iter().map(|(name, _)| (*name).to_string()).collect();
    linked_names.sort();
    assert_eq!(json_names, linked_names);
}

fn parse_ffi_json_symbol_names(json: &str) -> (u32, Vec<String>) {
    let parsed: serde_json::Value = serde_json::from_str(json).expect("ffi.json is JSON");
    let obj = parsed.as_object().expect("ffi.json object");
    let abi_version = obj
        .get("abi_version")
        .and_then(|value| value.as_u64())
        .expect("abi_version") as u32;
    let symbols = obj
        .get("symbols")
        .and_then(|value| value.as_array())
        .expect("symbols");
    let names = symbols
        .iter()
        .map(|symbol| {
            symbol
                .get("name")
                .and_then(|value| value.as_str())
                .expect("symbol name")
                .to_string()
        })
        .collect();
    (abi_version, names)
}

fn no_mangle_fn_names(src: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut pending = false;
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed == "#[no_mangle]" {
            pending = true;
            continue;
        }
        if pending {
            pending = false;
            if let Some(after) = trimmed.strip_prefix("pub extern \"C\" fn ") {
                let name = after.split('(').next().expect("fn name").to_string();
                names.push(name);
            }
        }
    }
    names
}
