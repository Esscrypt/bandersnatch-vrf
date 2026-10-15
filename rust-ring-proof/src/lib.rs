pub mod ietf;
pub mod vrf;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use pbnjam_ring_proof_core::RingBatchItemBytes;

#[napi]
pub fn prove_ring_proof(
    srs_bytes: Buffer,
    ring_keys_bytes: Buffer,
    blinding_factor_bytes: Buffer,
    prover_index: u32,
) -> Result<Buffer> {
    pbnjam_ring_proof_core::prove_ring_proof(
        srs_bytes.as_ref(),
        ring_keys_bytes.as_ref(),
        blinding_factor_bytes.as_ref(),
        prover_index,
    )
    .map(Buffer::from)
    .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn compute_ring_commitment(srs_bytes: Buffer, ring_keys_bytes: Buffer) -> Result<Buffer> {
    pbnjam_ring_proof_core::compute_ring_commitment(srs_bytes.as_ref(), ring_keys_bytes.as_ref())
        .map(Buffer::from)
        .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn verify_ring_vrf(
    srs_bytes: Buffer,
    proof_bytes: Buffer,
    ring_keys_bytes: Buffer,
    key_commitment_bytes: Buffer,
) -> Result<bool> {
    pbnjam_ring_proof_core::verify_ring_vrf(
        srs_bytes.as_ref(),
        proof_bytes.as_ref(),
        ring_keys_bytes.as_ref(),
        key_commitment_bytes.as_ref(),
    )
    .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn compute_ring_verifier_key(
    srs_bytes: Buffer,
    ring_keys_bytes: Buffer,
) -> Result<Buffer> {
    pbnjam_ring_proof_core::compute_ring_verifier_key(srs_bytes.as_ref(), ring_keys_bytes.as_ref())
        .map(Buffer::from)
        .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn verify_ring_vrf_with_key(
    vk_bytes: Buffer,
    proof_bytes: Buffer,
    key_commitment_bytes: Buffer,
    ring_size: u32,
) -> Result<bool> {
    pbnjam_ring_proof_core::verify_ring_vrf_with_key(
        vk_bytes.as_ref(),
        proof_bytes.as_ref(),
        key_commitment_bytes.as_ref(),
        ring_size,
    )
    .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi(object)]
pub struct RingBatchItem {
    pub proof_bytes: Buffer,
    pub key_commitment_bytes: Buffer,
}

#[napi]
pub fn batch_verify_ring_vrf(
    vk_bytes: Buffer,
    ring_size: u32,
    items: Vec<RingBatchItem>,
) -> Result<bool> {
    let items: Vec<RingBatchItemBytes> = items
        .into_iter()
        .map(|item| RingBatchItemBytes {
            proof_bytes: item.proof_bytes.to_vec(),
            key_commitment_bytes: item.key_commitment_bytes.to_vec(),
        })
        .collect();
    pbnjam_ring_proof_core::batch_verify_ring_vrf(vk_bytes.as_ref(), ring_size, &items)
        .map_err(|e| Error::from_reason(e.to_string()))
}
