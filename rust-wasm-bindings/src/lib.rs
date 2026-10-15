#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::needless_return)]

use wasm_bindgen::prelude::*;

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

#[wasm_bindgen]
pub fn compute_ring_commitment(
    srs_bytes: &[u8],
    ring_keys_bytes: &[u8],
    ring_size: usize,
) -> Result<Vec<u8>, JsValue> {
    use ark_vrf::ring::PcsParams;
    let pcs_params = PcsParams::<BandersnatchSha512Ell2>::deserialize_uncompressed_unchecked(&mut &srs_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize SRS: {:?}", e)))?;

    let key_size = 32;
    if ring_keys_bytes.len() % key_size != 0 {
        return Err(JsValue::from_str("Invalid ring keys length"));
    }
    let num_keys = ring_keys_bytes.len() / key_size;
    
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
            match EdwardsAffine::deserialize_compressed_unchecked(key_bytes) {
                Ok(k) => k,
                Err(_) => {
                    padding_point.clone()
                }
            }
        };
        ring_keys.push(key);
    }

    let params = RingProofParams::<BandersnatchSha512Ell2>::from_pcs_params(ring_size, pcs_params)
        .map_err(|e| JsValue::from_str(&format!("Failed to create ring proof params: {:?}", e)))?;

    let verifier_key = params.verifier_key(&ring_keys);
    let commitment = verifier_key.commitment();

    let mut result = Vec::with_capacity(144);
    commitment.points[0].serialize_compressed(&mut result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize cx: {:?}", e)))?;
    commitment.points[1].serialize_compressed(&mut result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize cy: {:?}", e)))?;
    commitment.ring_selector.serialize_compressed(&mut result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize selector: {:?}", e)))?;

    Ok(result)
}

#[wasm_bindgen]
pub fn prove_ring_proof(
    srs_bytes: &[u8],
    ring_keys_bytes: &[u8],
    blinding_factor_bytes: &[u8],
    prover_index: usize,
    ring_size: usize,
) -> Result<Vec<u8>, JsValue> {

    use ark_vrf::ring::PcsParams;
    let pcs_params = PcsParams::<BandersnatchSha512Ell2>::deserialize_uncompressed_unchecked(&mut &srs_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize SRS: {:?}", e)))?;

    let key_size = 32;
    if ring_keys_bytes.len() % key_size != 0 {
        return Err(JsValue::from_str("Invalid ring keys length"));
    }
    let num_keys = ring_keys_bytes.len() / key_size;
    
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

    use ark_ed_on_bls12_381_bandersnatch::Fr;
    let blinding_factor = Fr::deserialize_compressed(blinding_factor_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize blinding factor: {:?}", e)))?;

    let params = RingProofParams::<BandersnatchSha512Ell2>::from_pcs_params(ring_size, pcs_params)
        .map_err(|e| JsValue::from_str(&format!("Failed to create ring proof params: {:?}", e)))?;

    let prover_key = params.prover_key(&ring_keys);
    let prover = params.prover(prover_key, prover_index);

    let proof = prover.prove(blinding_factor);

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize proof: {:?}", e)))?;

    Ok(proof_bytes)
}

#[wasm_bindgen]
pub fn verify_ring_proof(
    srs_bytes: &[u8],
    proof_bytes: &[u8],
    ring_keys_bytes: &[u8],
    key_commitment_bytes: &[u8],
    ring_size: usize,
) -> Result<bool, JsValue> {
    use ark_vrf::ring::PcsParams;
    let pcs_params = PcsParams::<BandersnatchSha512Ell2>::deserialize_uncompressed_unchecked(&mut &srs_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize SRS: {:?}", e)))?;

    use ark_vrf::ring::RingBareProof;
    let proof = RingBareProof::<BandersnatchSha512Ell2>::deserialize_compressed(&mut &proof_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize proof (len={}): {:?}", proof_bytes.len(), e)))?;

    let key_size = 32;
    if ring_keys_bytes.len() % key_size != 0 {
        return Err(JsValue::from_str("Invalid ring keys length"));
    }
    let num_keys = ring_keys_bytes.len() / key_size;
    
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

    let key_commitment = EdwardsAffine::deserialize_compressed(key_commitment_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize key commitment: {:?}", e)))?;

    let params = RingProofParams::<BandersnatchSha512Ell2>::from_pcs_params(ring_size, pcs_params)
        .map_err(|e| JsValue::from_str(&format!("Failed to create ring proof params: {:?}", e)))?;

    let verifier_key = params.verifier_key(&ring_keys);
    let verifier = params.verifier(verifier_key);

    let is_valid = verifier.verify(proof, key_commitment);

    Ok(is_valid)
}

#[wasm_bindgen]
pub fn verify_ietf_vrf(
    public_key_bytes: &[u8],
    input_point_bytes: &[u8],
    output_point_bytes: &[u8],
    proof_bytes: &[u8],
    aux_data: &[u8],
) -> Result<bool, JsValue> {
    const POINT_LEN: usize = 32;
    const PROOF_LEN: usize = BandersnatchSha512Ell2::CHALLENGE_LEN + 32;

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
