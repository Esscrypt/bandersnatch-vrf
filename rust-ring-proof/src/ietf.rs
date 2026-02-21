//! IETF VRF (RFC-9381) prove and verify via napi-rs.
//!
//! Matches the ark-vrf BandersnatchSha512Ell2 suite used by the WASM bindings.
//! TypeScript handles serialization format validation; Rust handles the crypto.
//!
//! Proof wire format: gamma (32 bytes) || c (32 bytes) || s (32 bytes) = 96 bytes total.
//! This matches the format produced and consumed by the TypeScript IETFVRFProver / IETFVRFVerifierWasm.

use napi::bindgen_prelude::*;
use napi_derive::napi;

use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::{
    ietf::{Proof as IetfProof, Prover as IetfProver, Verifier as IetfVerifier},
    suites::bandersnatch::BandersnatchSha512Ell2,
    Input, Output, Public, Secret,
};

const GAMMA_LEN: usize = 32;
const PROOF_TOTAL_LEN: usize = 96; // gamma (32) + c (32) + s (32)

/// Prove IETF VRF (RFC-9381) using ark-vrf BandersnatchSha512Ell2.
///
/// # Arguments (pre-validated in TypeScript)
/// * `secret_key_bytes` - Secret scalar (32 bytes, little-endian Fr)
/// * `input_bytes` - Raw VRF input data (hashed to curve internally via Elligator2)
/// * `aux_data` - Additional data bound to the proof (may be empty)
///
/// # Returns
/// 96 bytes: gamma (32) || c (32) || s (32)
#[napi]
pub fn prove_ietf_vrf(
    secret_key_bytes: Buffer,
    input_bytes: Buffer,
    aux_data: Buffer,
) -> Result<Buffer> {
    let sk_bytes = secret_key_bytes.as_ref();
    let input_slice = input_bytes.as_ref();
    let aux_slice = aux_data.as_ref();

    let scalar = Fr::deserialize_compressed(sk_bytes)
        .map_err(|e| Error::from_reason(format!("Failed to deserialize secret key: {:?}", e)))?;

    let secret = Secret::<BandersnatchSha512Ell2>::from_scalar(scalar);

    let input = Input::<BandersnatchSha512Ell2>::new(input_slice)
        .ok_or_else(|| Error::from_reason("Failed to hash input to curve"))?;

    let output = secret.output(input);

    let proof: IetfProof<BandersnatchSha512Ell2> = secret.prove(input, output, aux_slice);

    let mut result = Vec::with_capacity(PROOF_TOTAL_LEN);
    output
        .0
        .serialize_compressed(&mut result)
        .map_err(|e| Error::from_reason(format!("Failed to serialize gamma: {:?}", e)))?;
    proof
        .serialize_compressed(&mut result)
        .map_err(|e| Error::from_reason(format!("Failed to serialize proof: {:?}", e)))?;

    Ok(result.into())
}

/// Verify IETF VRF proof (RFC-9381) using ark-vrf BandersnatchSha512Ell2.
///
/// # Arguments (pre-validated in TypeScript)
/// * `public_key_bytes` - Public key point (32 bytes, compressed)
/// * `input_bytes` - Raw VRF input data (hashed to curve internally via Elligator2)
/// * `proof_bytes` - 96-byte proof: gamma (32) || c (32) || s (32)
/// * `aux_data` - Additional data bound to the proof (may be empty)
///
/// # Returns
/// `true` if proof is valid, `false` otherwise.
#[napi]
pub fn verify_ietf_vrf(
    public_key_bytes: Buffer,
    input_bytes: Buffer,
    proof_bytes: Buffer,
    aux_data: Buffer,
) -> Result<bool> {
    let pk_slice = public_key_bytes.as_ref();
    let input_slice = input_bytes.as_ref();
    let proof_slice = proof_bytes.as_ref();
    let aux_slice = aux_data.as_ref();

    if proof_slice.len() != PROOF_TOTAL_LEN {
        return Err(Error::from_reason(format!(
            "Invalid proof length: expected {} bytes, got {}",
            PROOF_TOTAL_LEN,
            proof_slice.len()
        )));
    }

    let pk_point = EdwardsAffine::deserialize_compressed(pk_slice)
        .map_err(|e| Error::from_reason(format!("Failed to deserialize public key: {:?}", e)))?;
    let public = Public::<BandersnatchSha512Ell2>::from(pk_point);

    let input = Input::<BandersnatchSha512Ell2>::new(input_slice)
        .ok_or_else(|| Error::from_reason("Failed to hash input to curve"))?;

    let gamma = EdwardsAffine::deserialize_compressed(&proof_slice[..GAMMA_LEN])
        .map_err(|e| Error::from_reason(format!("Failed to deserialize gamma: {:?}", e)))?;
    let output = Output::<BandersnatchSha512Ell2>::from(gamma);

    let proof = IetfProof::<BandersnatchSha512Ell2>::deserialize_compressed(
        &mut &proof_slice[GAMMA_LEN..],
    )
    .map_err(|e| Error::from_reason(format!("Failed to deserialize proof (c||s): {:?}", e)))?;

    Ok(public.verify(input, output, aux_slice, &proof).is_ok())
}
