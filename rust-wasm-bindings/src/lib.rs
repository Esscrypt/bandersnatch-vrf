#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::needless_return)]

use wasm_bindgen::prelude::*;

// Panic hook for better error messages in the browser console
#[cfg(feature = "console_error_panic_hook")]
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

use ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::{
    ietf::{Proof as IetfProof, Verifier as IetfVerifier},
    ring::RingProofParams,
    suites::bandersnatch::{BandersnatchSha512Ell2, Input, Output},
    Public, Suite,
};

/// Compute ring commitment (FixedColumnsCommitted) from ring keys.
/// This matches ark-vrf's RingProofParams::verifier_key().commitment() functionality.
///
/// # Arguments
/// * `srs_bytes` - Serialized PCS params (SRS) bytes (uncompressed arkworks format)
/// * `ring_keys_bytes` - Serialized ring public keys (compressed, 32 bytes each)
/// * `ring_size` - Number of keys in the ring
///
/// # Returns
/// * Serialized FixedColumnsCommitted (144 bytes: cx, cy, selector, each 48 bytes)
#[wasm_bindgen]
pub fn compute_ring_commitment(
    srs_bytes: &[u8],
    ring_keys_bytes: &[u8],
    ring_size: usize,
) -> Result<Vec<u8>, JsValue> {
    // Deserialize SRS (PCS params)
    use ark_vrf::ring::PcsParams;
    let pcs_params = PcsParams::<BandersnatchSha512Ell2>::deserialize_uncompressed_unchecked(&mut &srs_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize SRS: {:?}", e)))?;

    // Deserialize ring keys using unchecked deserialization
    // Gray Paper bandersnatch.tex line 20: padding point should be substituted for invalid keys
    // This includes null keys (all zeros) and keys that fail deserialization
    let key_size = 32;
    if ring_keys_bytes.len() % key_size != 0 {
        return Err(JsValue::from_str("Invalid ring keys length"));
    }
    let num_keys = ring_keys_bytes.len() / key_size;
    
    // Padding point from bandersnatch-vrf-spec section 4.1 (compressed Twisted Edwards form)
    // Derived using ECVRF_encode_to_curve with input "ring-proof-pad"
    let padding_point_bytes: [u8; 32] = [
        0x92, 0xca, 0x79, 0xe6, 0x1d, 0xd9, 0x0c, 0x15,
        0x73, 0xa8, 0x69, 0x3f, 0x19, 0x9b, 0xf6, 0xe1,
        0xe8, 0x68, 0x35, 0xcc, 0x71, 0x5c, 0xdc, 0xf9,
        0x3f, 0x5e, 0xf2, 0x22, 0x56, 0x00, 0x23, 0xaa
    ];
    let padding_point = EdwardsAffine::deserialize_compressed_unchecked(&padding_point_bytes[..])
        .expect("Padding point should always deserialize");
    
    let mut ring_keys = Vec::new();
    for i in 0..num_keys {
        let key_bytes = &ring_keys_bytes[i * key_size..(i + 1) * key_size];
        
        // Check for null key (all zeros)
        let is_null_key = key_bytes.iter().all(|&b| b == 0);
        
        // Try to deserialize, use padding point if null or invalid
        let key = if is_null_key {
            padding_point.clone()
        } else {
            match EdwardsAffine::deserialize_compressed_unchecked(key_bytes) {
                Ok(k) => k,
                Err(_) => {
                    // Invalid key - replace with padding point per Gray Paper
                    padding_point.clone()
                }
            }
        };
        ring_keys.push(key);
    }

    // Create ring proof params from PCS params
    let params = RingProofParams::<BandersnatchSha512Ell2>::from_pcs_params(ring_size, pcs_params)
        .map_err(|e| JsValue::from_str(&format!("Failed to create ring proof params: {:?}", e)))?;

    // Create verifier key and get commitment
    let verifier_key = params.verifier_key(&ring_keys);
    let commitment = verifier_key.commitment();

    // Serialize commitment (points[0]=cx, points[1]=cy, ring_selector=selector)
    let mut result = Vec::with_capacity(144);
    commitment.points[0].serialize_compressed(&mut result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize cx: {:?}", e)))?;
    commitment.points[1].serialize_compressed(&mut result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize cy: {:?}", e)))?;
    commitment.ring_selector.serialize_compressed(&mut result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize selector: {:?}", e)))?;

    Ok(result)
}

/// Generate a ring proof using ark-vrf (matches test vectors exactly).
///
/// This function uses ark-vrf's RingProver which matches the exact implementation
/// used to generate the test vectors.
///
/// # Arguments
/// * `srs_bytes` - Serialized PCS params (SRS) bytes (uncompressed arkworks format)
/// * `ring_keys_bytes` - Serialized ring public keys (compressed, 32 bytes each)
/// * `blinding_factor_bytes` - Serialized blinding factor (32 bytes, Fr scalar)
/// * `prover_index` - Index of the prover's key in the ring (0-based)
/// * `ring_size` - Number of keys in the ring
///
/// # Returns
/// * Serialized RingProof (matches test vectors exactly)
#[wasm_bindgen]
pub fn prove_ring_proof(
    srs_bytes: &[u8],
    ring_keys_bytes: &[u8],
    blinding_factor_bytes: &[u8],
    prover_index: usize,
    ring_size: usize,
) -> Result<Vec<u8>, JsValue> {

    // Deserialize SRS (PCS params)
    use ark_vrf::ring::PcsParams;
    let pcs_params = PcsParams::<BandersnatchSha512Ell2>::deserialize_uncompressed_unchecked(&mut &srs_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize SRS: {:?}", e)))?;

    // Deserialize ring keys using unchecked deserialization
    // Gray Paper bandersnatch.tex line 20: padding point should be substituted for invalid keys
    let key_size = 32;
    if ring_keys_bytes.len() % key_size != 0 {
        return Err(JsValue::from_str("Invalid ring keys length"));
    }
    let num_keys = ring_keys_bytes.len() / key_size;
    
    // Padding point from bandersnatch-vrf-spec section 4.1
    let padding_point_bytes: [u8; 32] = [
        0x92, 0xca, 0x79, 0xe6, 0x1d, 0xd9, 0x0c, 0x15,
        0x73, 0xa8, 0x69, 0x3f, 0x19, 0x9b, 0xf6, 0xe1,
        0xe8, 0x68, 0x35, 0xcc, 0x71, 0x5c, 0xdc, 0xf9,
        0x3f, 0x5e, 0xf2, 0x22, 0x56, 0x00, 0x23, 0xaa
    ];
    let padding_point = EdwardsAffine::deserialize_compressed_unchecked(&padding_point_bytes[..])
        .expect("Padding point should always deserialize");
    
    let mut ring_keys = Vec::new();
    for i in 0..num_keys {
        let key_bytes = &ring_keys_bytes[i * key_size..(i + 1) * key_size];
        let is_null_key = key_bytes.iter().all(|&b| b == 0);
        let key = if is_null_key {
            padding_point.clone()
        } else {
            EdwardsAffine::deserialize_compressed_unchecked(key_bytes).unwrap_or(padding_point.clone())
        };
        ring_keys.push(key);
    }

    if prover_index >= num_keys {
        return Err(JsValue::from_str("Prover index out of bounds"));
    }

    // Deserialize blinding factor
    use ark_ed_on_bls12_381_bandersnatch::Fr;
    let blinding_factor = Fr::deserialize_compressed(blinding_factor_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize blinding factor: {:?}", e)))?;

    // Create ring proof params from PCS params
    let params = RingProofParams::<BandersnatchSha512Ell2>::from_pcs_params(ring_size, pcs_params)
        .map_err(|e| JsValue::from_str(&format!("Failed to create ring proof params: {:?}", e)))?;

    // Create prover key and prover instance (matches ark-vrf exactly)
    let prover_key = params.prover_key(&ring_keys);
    let prover = params.prover(prover_key, prover_index);

    // Generate proof using blinding factor (matches ark-vrf::ring::Prover::prove)
    let proof = prover.prove(blinding_factor);

    // Serialize proof
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize proof: {:?}", e)))?;

    Ok(proof_bytes)
}

/// Verify a ring proof using ark-vrf.
///
/// # Arguments
/// * `srs_bytes` - Serialized PCS params (SRS) bytes (uncompressed arkworks format)
/// * `proof_bytes` - Serialized RingProof
/// * `ring_keys_bytes` - Serialized ring public keys (compressed, 32 bytes each)
/// * `key_commitment_bytes` - Serialized key commitment (Y_bar from Pedersen proof, compressed, 32 bytes)
/// * `ring_size` - Number of keys in the ring
///
/// # Returns
/// * `true` if proof is valid, `false` otherwise
#[wasm_bindgen]
pub fn verify_ring_proof(
    srs_bytes: &[u8],
    proof_bytes: &[u8],
    ring_keys_bytes: &[u8],
    key_commitment_bytes: &[u8],
    ring_size: usize,
) -> Result<bool, JsValue> {
    // Deserialize SRS (PCS params)
    use ark_vrf::ring::PcsParams;
    let pcs_params = PcsParams::<BandersnatchSha512Ell2>::deserialize_uncompressed_unchecked(&mut &srs_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize SRS: {:?}", e)))?;

    // Deserialize proof
    // NOTE: proof_bytes should ONLY contain the compressed RingBareProof bytes,
    // NOT the full 784-byte structure (which includes gamma, pedersen_proof, ring_commitment).
    // The ring proof portion is extracted from the 784-byte structure before calling this function.
    use ark_vrf::ring::RingBareProof;
    // deserialize_compressed needs a mutable reference to a Read trait object
    // &mut &[u8] implements Read and allows the deserializer to consume bytes
    let proof = RingBareProof::<BandersnatchSha512Ell2>::deserialize_compressed(&mut &proof_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize proof (len={}): {:?}", proof_bytes.len(), e)))?;

    // Deserialize ring keys using unchecked deserialization
    // Gray Paper bandersnatch.tex line 20: padding point should be substituted for invalid keys
    let key_size = 32;
    if ring_keys_bytes.len() % key_size != 0 {
        return Err(JsValue::from_str("Invalid ring keys length"));
    }
    let num_keys = ring_keys_bytes.len() / key_size;
    
    // Padding point from bandersnatch-vrf-spec section 4.1
    let padding_point_bytes: [u8; 32] = [
        0x92, 0xca, 0x79, 0xe6, 0x1d, 0xd9, 0x0c, 0x15,
        0x73, 0xa8, 0x69, 0x3f, 0x19, 0x9b, 0xf6, 0xe1,
        0xe8, 0x68, 0x35, 0xcc, 0x71, 0x5c, 0xdc, 0xf9,
        0x3f, 0x5e, 0xf2, 0x22, 0x56, 0x00, 0x23, 0xaa
    ];
    let padding_point = EdwardsAffine::deserialize_compressed_unchecked(&padding_point_bytes[..])
        .expect("Padding point should always deserialize");
    
    let mut ring_keys = Vec::new();
    for i in 0..num_keys {
        let key_bytes = &ring_keys_bytes[i * key_size..(i + 1) * key_size];
        let is_null_key = key_bytes.iter().all(|&b| b == 0);
        let key = if is_null_key {
            padding_point.clone()
        } else {
            EdwardsAffine::deserialize_compressed_unchecked(key_bytes).unwrap_or(padding_point.clone())
        };
        ring_keys.push(key);
    }

    // Deserialize key commitment (Y_bar from Pedersen proof)
    let key_commitment = EdwardsAffine::deserialize_compressed(key_commitment_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize key commitment: {:?}", e)))?;

    // Create ring proof params from PCS params
    let params = RingProofParams::<BandersnatchSha512Ell2>::from_pcs_params(ring_size, pcs_params)
        .map_err(|e| JsValue::from_str(&format!("Failed to create ring proof params: {:?}", e)))?;

    // Create verifier key and verifier instance
    let verifier_key = params.verifier_key(&ring_keys);
    let verifier = params.verifier(verifier_key);

    // Verify proof (matches ark-vrf::ring::Verifier::verify)
    let is_valid = verifier.verify(proof, key_commitment);

    Ok(is_valid)
}

/// Verify an IETF VRF proof using ark-vrf (RFC-9381).
///
/// # Arguments
/// * `public_key_bytes` - Public key point (32 bytes, compressed)
/// * `input_point_bytes` - VRF input point alpha / H (32 bytes, compressed)
/// * `output_point_bytes` - VRF output point gamma (32 bytes, compressed)
/// * `proof_bytes` - IETF proof (64 bytes: c || s, both little-endian)
/// * `aux_data` - Additional data bound to the proof
///
/// # Returns
/// * `true` if proof is valid, `false` otherwise
#[wasm_bindgen]
pub fn verify_ietf_vrf(
    public_key_bytes: &[u8],
    input_point_bytes: &[u8],
    output_point_bytes: &[u8],
    proof_bytes: &[u8],
    aux_data: &[u8],
) -> Result<bool, JsValue> {
    const POINT_LEN: usize = 32;
    const PROOF_LEN: usize = BandersnatchSha512Ell2::CHALLENGE_LEN + 32; // c + s (scalar compressed)

    if public_key_bytes.len() != POINT_LEN
        || input_point_bytes.len() != POINT_LEN
        || output_point_bytes.len() != POINT_LEN
    {
        return Err(JsValue::from_str("Invalid point length (expected 32 bytes each)"));
    }
    if proof_bytes.len() != PROOF_LEN {
        return Err(JsValue::from_str(&format!(
            "Invalid proof length (expected {} bytes)",
            PROOF_LEN
        )));
    }

    // Padding point from bandersnatch-vrf-spec section 4.1
    let padding_point_bytes: [u8; 32] = [
        0x92, 0xca, 0x79, 0xe6, 0x1d, 0xd9, 0x0c, 0x15,
        0x73, 0xa8, 0x69, 0x3f, 0x19, 0x9b, 0xf6, 0xe1,
        0xe8, 0x68, 0x35, 0xcc, 0x71, 0x5c, 0xdc, 0xf9,
        0x3f, 0x5e, 0xf2, 0x22, 0x56, 0x00, 0x23, 0xaa
    ];
    let padding_point = EdwardsAffine::deserialize_compressed_unchecked(&padding_point_bytes[..])
        .expect("Padding point should always deserialize");

    let deserialize_point_or_padding = |bytes: &[u8]| -> EdwardsAffine {
        if bytes.iter().all(|&b| b == 0) {
            return padding_point;
        }
        EdwardsAffine::deserialize_compressed_unchecked(bytes).unwrap_or(padding_point)
    };

    let public = Public::<BandersnatchSha512Ell2>(deserialize_point_or_padding(public_key_bytes));
    let input = Input::from(deserialize_point_or_padding(input_point_bytes));
    let output = Output::from(deserialize_point_or_padding(output_point_bytes));

    let proof = IetfProof::<BandersnatchSha512Ell2>::deserialize_compressed(&mut &proof_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize IETF proof: {:?}", e)))?;

    match public.verify(input, output, aux_data, &proof) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}
