use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi]
pub fn prove_ietf_vrf(
    secret_key_bytes: Buffer,
    input_bytes: Buffer,
    aux_data: Buffer,
) -> Result<Buffer> {
    pbnjam_ring_proof_core::prove_ietf_vrf(
        secret_key_bytes.as_ref(),
        input_bytes.as_ref(),
        aux_data.as_ref(),
    )
    .map(Buffer::from)
    .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn verify_ietf_vrf(
    public_key_bytes: Buffer,
    input_bytes: Buffer,
    proof_bytes: Buffer,
    aux_data: Buffer,
) -> Result<bool> {
    pbnjam_ring_proof_core::verify_ietf_vrf(
        public_key_bytes.as_ref(),
        input_bytes.as_ref(),
        proof_bytes.as_ref(),
        aux_data.as_ref(),
    )
    .map_err(|e| Error::from_reason(e.to_string()))
}
