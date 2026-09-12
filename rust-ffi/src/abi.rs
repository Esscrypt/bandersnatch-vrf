use crate::handles::{self, InsertError};
use crate::status::{self, fail, set_last_error, take_last_error};
use ark_bls12_381::Bls12_381;
use ark_serialize::CanonicalDeserialize;
use pbnjam_ring_proof_core::packed::{
    decode_bvrf_batch_verify_items, decode_bvrf_ietf_verify_request, decode_bvrf_ring_prepare_request,
    decode_bvrf_srs_open_request, encode_bvrf_batch_verify_items, encode_bvrf_last_error,
    encode_bvrf_ring_prepare_output, encode_bvrf_srs_open_output, encode_bvrf_validity, CodecError,
};
use pbnjam_ring_proof_core::{
    batch_verify_ring_vrf, compute_ring_commitment, compute_ring_verifier_key, verify_ietf_vrf,
    CoreError, RingBatchItemBytes,
};
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use w3f_pcs::pcs::kzg::urs::URS;

use crate::exported_symbols::ABI_VERSION;

const RING_KEY_LEN: usize = 32;

pub type PbnjamBytesCb = Option<extern "C" fn(*const u8, usize, *mut c_void)>;

fn with_catch_unwind<F>(body: F) -> i32
where
    F: FnOnce() -> i32,
{
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(code) => code,
        Err(payload) => {
            set_last_error(panic_message(payload));
            status::PANIC
        }
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "panic".to_string()
}

fn deliver(cb: PbnjamBytesCb, ctx: *mut c_void, payload: &[u8]) -> i32 {
    let Some(callback) = cb else {
        return fail(status::INVALID_ARGUMENT, "null output callback");
    };
    callback(payload.as_ptr(), payload.len(), ctx);
    status::SUCCESS
}

unsafe fn request_bytes<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(fail(
            status::INVALID_ARGUMENT,
            "null request pointer with non-zero length",
        ));
    }
    Ok(std::slice::from_raw_parts(ptr, len))
}

fn map_codec(err: CodecError) -> i32 {
    fail(status::MALFORMED, err.to_string())
}

fn map_core(err: CoreError) -> i32 {
    fail(status::NATIVE_FAILURE, err.to_string())
}

fn map_insert(err: InsertError) -> i32 {
    match err {
        InsertError::Exhausted => fail(status::RESOURCE_EXHAUSTION, "handle table exhausted"),
    }
}

fn parse_srs_fail_fast(bytes: &[u8]) -> Result<(), String> {
    const G1_UNCOMPRESSED: u64 = 96;
    const G2_UNCOMPRESSED: u64 = 192;
    if bytes.len() < 16 {
        return Err("SRS file too short to contain G1/G2 length prefixes".to_string());
    }
    let g1_len = u64::from_le_bytes(bytes[0..8].try_into().expect("8-byte G1 length"));
    let g1_bytes = g1_len
        .checked_mul(G1_UNCOMPRESSED)
        .ok_or_else(|| "SRS G1 length overflows".to_string())?;
    let after_g1 = 8u64
        .checked_add(g1_bytes)
        .ok_or_else(|| "SRS G1 section overflows".to_string())?;
    let g2_len_offset = after_g1
        .checked_add(8)
        .ok_or_else(|| "SRS G2 length prefix overflows".to_string())?;
    if g2_len_offset > bytes.len() as u64 {
        return Err("SRS file too short for declared G1 points".to_string());
    }
    let g2_offset = after_g1 as usize;
    let g2_len = u64::from_le_bytes(
        bytes[g2_offset..g2_offset + 8]
            .try_into()
            .expect("8-byte G2 length"),
    );
    let g2_bytes = g2_len
        .checked_mul(G2_UNCOMPRESSED)
        .ok_or_else(|| "SRS G2 length overflows".to_string())?;
    let expected = g2_len_offset
        .checked_add(g2_bytes)
        .ok_or_else(|| "SRS layout overflows".to_string())?;
    if expected != bytes.len() as u64 {
        return Err(format!(
            "SRS file layout mismatch: expected {expected} uncompressed bytes, got {}",
            bytes.len()
        ));
    }

    type PcsParams = URS<Bls12_381>;
    match catch_unwind(AssertUnwindSafe(|| {
        PcsParams::deserialize_uncompressed_unchecked(&mut &bytes[..])
    })) {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(format!("Failed to deserialize SRS: {err:?}")),
        Err(payload) => Err(format!(
            "Failed to deserialize SRS: {}",
            panic_message(payload)
        )),
    }
}

fn srs_open_inner(
    req: *const u8,
    req_len: usize,
    out_cb: PbnjamBytesCb,
    ctx: *mut c_void,
) -> i32 {
    if out_cb.is_none() {
        return fail(status::INVALID_ARGUMENT, "null output callback");
    }
    let request = match unsafe { request_bytes(req, req_len) } {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    let path = match decode_bvrf_srs_open_request(request) {
        Ok(path) => path,
        Err(err) => return map_codec(err),
    };
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return fail(
                status::NATIVE_FAILURE,
                format!("failed to read SRS file {path}: {err}"),
            )
        }
    };
    if let Err(message) = parse_srs_fail_fast(&bytes) {
        return fail(status::NATIVE_FAILURE, message);
    }
    let handle = match handles::insert_srs(bytes) {
        Ok(handle) => handle,
        Err(err) => return map_insert(err),
    };
    deliver(out_cb, ctx, &encode_bvrf_srs_open_output(handle))
}

fn ring_prepare_inner(
    srs_handle: u32,
    req: *const u8,
    req_len: usize,
    out_cb: PbnjamBytesCb,
    ctx: *mut c_void,
) -> i32 {
    if out_cb.is_none() {
        return fail(status::INVALID_ARGUMENT, "null output callback");
    }
    let srs = match handles::get_srs(srs_handle) {
        Ok(bytes) => bytes,
        Err(()) => return fail(status::UNKNOWN_HANDLE, "unknown or stale SRS handle"),
    };
    let request = match unsafe { request_bytes(req, req_len) } {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    let ring_keys = match decode_bvrf_ring_prepare_request(request) {
        Ok(keys) => keys,
        Err(err) => return map_codec(err),
    };
    if ring_keys.len() % RING_KEY_LEN != 0 {
        return fail(
            status::INVALID_ARGUMENT,
            format!(
                "ring keys length {} is not a multiple of {RING_KEY_LEN}",
                ring_keys.len()
            ),
        );
    }
    let commitment = match compute_ring_commitment(&srs, &ring_keys) {
        Ok(bytes) => bytes,
        Err(err) => return map_core(err),
    };
    let verifier_key = match compute_ring_verifier_key(&srs, &ring_keys) {
        Ok(bytes) => bytes,
        Err(err) => return map_core(err),
    };
    let handle = match handles::insert_ring(verifier_key) {
        Ok(handle) => handle,
        Err(err) => return map_insert(err),
    };
    match encode_bvrf_ring_prepare_output(handle, &commitment) {
        Ok(payload) => deliver(out_cb, ctx, &payload),
        Err(err) => {
            let _ = handles::release_ring(handle);
            map_codec(err)
        }
    }
}

fn ring_batch_verify_inner(
    ring_handle: u32,
    ring_size: u32,
    req: *const u8,
    req_len: usize,
    out_cb: PbnjamBytesCb,
    ctx: *mut c_void,
) -> i32 {
    if out_cb.is_none() {
        return fail(status::INVALID_ARGUMENT, "null output callback");
    }
    let verifier_key = match handles::get_ring(ring_handle) {
        Ok(bytes) => bytes,
        Err(()) => return fail(status::UNKNOWN_HANDLE, "unknown or stale ring handle"),
    };
    let request = match unsafe { request_bytes(req, req_len) } {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    let items = match decode_bvrf_batch_verify_items(request) {
        Ok(items) => items,
        Err(err) => return map_codec(err),
    };
    if let Err(err) = encode_bvrf_batch_verify_items(&items) {
        return map_codec(err);
    }
    let core_items: Vec<RingBatchItemBytes> = items
        .into_iter()
        .map(|item| RingBatchItemBytes {
            proof_bytes: item.proof,
            key_commitment_bytes: item.key_commitment,
        })
        .collect();
    match batch_verify_ring_vrf(&verifier_key, ring_size, &core_items) {
        Ok(valid) => deliver(out_cb, ctx, &encode_bvrf_validity(valid)),
        Err(err) => map_core(err),
    }
}

fn ietf_verify_inner(
    req: *const u8,
    req_len: usize,
    out_cb: PbnjamBytesCb,
    ctx: *mut c_void,
) -> i32 {
    if out_cb.is_none() {
        return fail(status::INVALID_ARGUMENT, "null output callback");
    }
    let request = match unsafe { request_bytes(req, req_len) } {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    let decoded = match decode_bvrf_ietf_verify_request(request) {
        Ok(decoded) => decoded,
        Err(err) => return map_codec(err),
    };
    match verify_ietf_vrf(
        &decoded.public_key,
        &decoded.input,
        &decoded.proof,
        &decoded.aux,
    ) {
        Ok(valid) => deliver(out_cb, ctx, &encode_bvrf_validity(valid)),
        Err(err) => map_core(err),
    }
}

fn take_last_error_inner(out_cb: PbnjamBytesCb, ctx: *mut c_void) -> i32 {
    if out_cb.is_none() {
        return fail(status::INVALID_ARGUMENT, "null output callback");
    }
    let message = take_last_error().unwrap_or_default();
    deliver(out_cb, ctx, &encode_bvrf_last_error(&message))
}

#[no_mangle]
pub extern "C" fn pbnjam_bvrf_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub extern "C" fn pbnjam_bvrf_srs_open(
    req: *const u8,
    req_len: usize,
    out_cb: PbnjamBytesCb,
    ctx: *mut c_void,
) -> i32 {
    with_catch_unwind(|| srs_open_inner(req, req_len, out_cb, ctx))
}

#[no_mangle]
pub extern "C" fn pbnjam_bvrf_srs_release(handle: u32) -> i32 {
    with_catch_unwind(|| match handles::release_srs(handle) {
        Ok(()) => status::SUCCESS,
        Err(()) => fail(status::UNKNOWN_HANDLE, "unknown or stale SRS handle"),
    })
}

#[no_mangle]
pub extern "C" fn pbnjam_bvrf_ring_prepare(
    srs_handle: u32,
    req: *const u8,
    req_len: usize,
    out_cb: PbnjamBytesCb,
    ctx: *mut c_void,
) -> i32 {
    with_catch_unwind(|| ring_prepare_inner(srs_handle, req, req_len, out_cb, ctx))
}

#[no_mangle]
pub extern "C" fn pbnjam_bvrf_ring_release(handle: u32) -> i32 {
    with_catch_unwind(|| match handles::release_ring(handle) {
        Ok(()) => status::SUCCESS,
        Err(()) => fail(status::UNKNOWN_HANDLE, "unknown or stale ring handle"),
    })
}

#[no_mangle]
pub extern "C" fn pbnjam_bvrf_ring_batch_verify(
    ring_handle: u32,
    ring_size: u32,
    req: *const u8,
    req_len: usize,
    out_cb: PbnjamBytesCb,
    ctx: *mut c_void,
) -> i32 {
    with_catch_unwind(|| ring_batch_verify_inner(ring_handle, ring_size, req, req_len, out_cb, ctx))
}

#[no_mangle]
pub extern "C" fn pbnjam_bvrf_ietf_verify(
    req: *const u8,
    req_len: usize,
    out_cb: PbnjamBytesCb,
    ctx: *mut c_void,
) -> i32 {
    with_catch_unwind(|| ietf_verify_inner(req, req_len, out_cb, ctx))
}

#[no_mangle]
pub extern "C" fn pbnjam_bvrf_take_last_error(out_cb: PbnjamBytesCb, ctx: *mut c_void) -> i32 {
    with_catch_unwind(|| take_last_error_inner(out_cb, ctx))
}

#[cfg(test)]
pub extern "C" fn pbnjam_bvrf_force_panic_for_test() -> i32 {
    with_catch_unwind(|| panic!("forced panic for Bandersnatch C ABI test"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::raw::c_void;

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

    fn take_last_error_string() -> String {
        let mut capture = Capture {
            data: Vec::new(),
            calls: 0,
        };
        let status = pbnjam_bvrf_take_last_error(
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        );
        assert_eq!(status, 0);
        assert_eq!(capture.calls, 1);
        pbnjam_ring_proof_core::packed::decode_bvrf_last_error(&capture.data)
            .expect("packed last error")
    }

    fn open_test_handle() -> u32 {
        handles::insert_srs(vec![0x01, 0x02, 0x03]).expect("test SRS handle")
    }

    #[test]
    fn released_handle_is_stale() {
        let handle = open_test_handle();
        assert_eq!(pbnjam_bvrf_srs_release(handle), 0);
        assert_eq!(pbnjam_bvrf_srs_release(handle), 3);
    }

    #[test]
    fn panic_becomes_status_five() {
        let status = pbnjam_bvrf_force_panic_for_test();
        assert_eq!(status, 5);
        let message = take_last_error_string();
        assert!(!message.is_empty());
    }

    #[test]
    fn null_callback_is_status_two() {
        let status = pbnjam_bvrf_take_last_error(None, std::ptr::null_mut());
        assert_eq!(status, 2);
    }

    #[test]
    fn srs_and_ring_handles_do_not_alias() {
        let srs_handle = handles::insert_srs(vec![0x11]).expect("srs");
        let ring_handle = handles::insert_ring(vec![0x22]).expect("ring");
        assert_ne!(srs_handle, ring_handle);

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
        let batch_status = pbnjam_bvrf_ring_batch_verify(
            srs_handle,
            8,
            req.as_ptr(),
            req.len(),
            Some(capture_cb),
            &mut capture as *mut Capture as *mut c_void,
        );
        assert_eq!(batch_status, 3);
        assert_eq!(capture.calls, 0);
        assert_eq!(pbnjam_bvrf_srs_release(ring_handle), 3);

        assert_eq!(pbnjam_bvrf_srs_release(srs_handle), 0);
        assert_eq!(pbnjam_bvrf_ring_release(ring_handle), 0);
    }
}
