//! Rust connector for ring proof generation and IETF VRF.
//!
//! Ring proof: handles core logic (RingPiopParams::setup, index, RingProver::init, prove).
//! IETF VRF: handles RFC-9381 prove and verify via ark-vrf BandersnatchSha512Ell2 suite.
//! TypeScript handles: validations, deserialization error handling, and proof serialization.

pub mod ietf;
pub mod vrf;
mod batch;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use ark_bls12_381::Bls12_381;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fq, Fr};
use ark_ff::MontFp;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use w3f_pcs::pcs::kzg::KZG;
use w3f_pcs::pcs::kzg::urs::URS;
use w3f_ring_proof::ring_prover::RingProver;
use w3f_ring_proof::ring_verifier::RingVerifier;
use w3f_ring_proof::VerifierKey as RingVerifierKey;
use w3f_ring_proof::ArkTranscript as RingArkTranscript;
use w3f_ring_proof::PiopParams as RingPiopParams;
use w3f_ring_proof::RingProof as W3fRingProof;
use w3f_ring_proof::Domain;

// --- ark-vrf algorithm (ring.rs): domain and SRS sizing without using ark-vrf ---


type PcsParams = URS<Bls12_381>;


const MODULUS_BIT_SIZE: usize = 255;



const fn piop_domain_size_from_ring_size(ring_size: usize) -> usize {
    (ring_size + 4 + MODULUS_BIT_SIZE).next_power_of_two()
}




const fn max_ring_size_from_piop_domain(piop_domain_size: usize) -> usize {
    piop_domain_size.saturating_sub(4 + MODULUS_BIT_SIZE)
}


const fn pcs_domain_size_from_ring_size(ring_size: usize) -> usize {
    3 * piop_domain_size_from_ring_size(ring_size) + 1
}


const PADDING_POINT_BYTES: [u8; 32] = [
    0x92, 0xca, 0x79, 0xe6, 0x1d, 0xd9, 0x0c, 0x15,
    0x73, 0xa8, 0x69, 0x3f, 0x19, 0x9b, 0xf6, 0xe1,
    0xe8, 0x68, 0x35, 0xcc, 0x71, 0x5c, 0xdc, 0xf9,
    0x3f, 0x5e, 0xf2, 0x22, 0x56, 0x00, 0x23, 0xaa,
];


const SUITE_ID: &[u8] = b"Bandersnatch_SHA-512_ELL2";


fn bandersnatch_blinding_base() -> EdwardsAffine {
    EdwardsAffine::new_unchecked(
        MontFp!("6150229251051246713677296363717454238956877613358614224171740096471278798312"),
        MontFp!("28442734166467795856797249030329035618871580593056783094884474814923353898473"),
    )
}


fn bandersnatch_accumulator_base() -> EdwardsAffine {
    EdwardsAffine::new_unchecked(
        MontFp!("37805570861274048643170021838972902516980894313648523898085159469000338764576"),
        MontFp!("14738305321141000190236674389841754997202271418876976886494444739226156422510"),
    )
}


fn bandersnatch_padding() -> EdwardsAffine {
    EdwardsAffine::new_unchecked(
        MontFp!("26287722405578650394504321825321286533153045350760430979437739593351290020913"),
        MontFp!("19058981610000167534379068105702216971787064146691007947119244515951752366738"),
    )
}


///


///





///


#[napi]
pub fn prove_ring_proof(
    srs_bytes: Buffer,
    ring_keys_bytes: Buffer,
    blinding_factor_bytes: Buffer,
    prover_index: u32,
) -> Result<Buffer> {
    let srs_bytes = srs_bytes.as_ref();
    let ring_keys_bytes = ring_keys_bytes.as_ref();
    let blinding_factor_bytes = blinding_factor_bytes.as_ref();

    const KEY_SIZE: usize = 32;
    if ring_keys_bytes.len() % KEY_SIZE != 0 {
        return Err(Error::from_reason("Invalid ring keys length"));
    }
    let ring_size = ring_keys_bytes.len() / KEY_SIZE;

    // Deserialize SRS (PCS params) — matches ark-vrf-wasm
    let mut pcs_params: PcsParams = PcsParams::deserialize_uncompressed_unchecked(&mut &srs_bytes[..])
        .map_err(|e| Error::from_reason(format!("Failed to deserialize SRS: {:?}", e)))?;
    let piop_domain_size = piop_domain_size_from_ring_size(ring_size);
    let pcs_domain_size = pcs_domain_size_from_ring_size(ring_size);

    if pcs_params.powers_in_g1.len() < pcs_domain_size || pcs_params.powers_in_g2.len() < 2 {
        return Err(Error::from_reason(format!(
            "SRS too small: need powers_in_g1.len() >= {} and powers_in_g2.len() >= 2, got {} and {}",
            pcs_domain_size,
            pcs_params.powers_in_g1.len(),
            pcs_params.powers_in_g2.len()
        )));
    }
    // Keep only the required powers of tau (matches ark-vrf from_pcs_params)
    pcs_params.powers_in_g1.truncate(pcs_domain_size);
    pcs_params.powers_in_g2.truncate(2);

    // Deserialize ring keys; null/invalid keys → padding point (matches ark-vrf-wasm)
    let padding_point = EdwardsAffine::deserialize_compressed_unchecked(&PADDING_POINT_BYTES[..])
        .expect("Padding point is valid");
    let mut ring_keys = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        let key_bytes = &ring_keys_bytes[i * KEY_SIZE..(i + 1) * KEY_SIZE];
        let is_null_key = key_bytes.iter().all(|&b| b == 0);
        let key = if is_null_key {
            padding_point
        } else {
            EdwardsAffine::deserialize_compressed_unchecked(key_bytes).unwrap_or(padding_point)
        };
        ring_keys.push(key);
    }

    // Deserialize blinding factor
    let blinding_factor = Fr::deserialize_compressed(blinding_factor_bytes)
        .map_err(|e| Error::from_reason(format!("Failed to deserialize blinding factor: {:?}", e)))?;

    // Ring proof params from PCS params (matches ark-vrf RingProofParams::from_pcs_params(ring_size, pcs_params))
    let domain = Domain::new(piop_domain_size, true);
    let h = bandersnatch_blinding_base();
    let seed = bandersnatch_accumulator_base();
    let padding = bandersnatch_padding();
    let ring_piop_params = RingPiopParams::setup(domain, h, seed, padding);
    let max_ring_size = max_ring_size_from_piop_domain(piop_domain_size);
    let keys_for_index: &[EdwardsAffine] = if ring_keys.len() <= max_ring_size {
        &ring_keys[..]
    } else {
        &ring_keys[..max_ring_size]
    };

    // Prover key and prover instance (matches ark-vrf params.prover_key, params.prover)
    let (prover_key, _verifier_key) =
        w3f_ring_proof::index::<_, KZG<Bls12_381>, _>(&pcs_params, &ring_piop_params, keys_for_index);

    let transcript = RingArkTranscript::new(SUITE_ID);
    let ring_prover = RingProver::init(
        prover_key,
        ring_piop_params,
        prover_index as usize,
        transcript,
    );
    // Generate proof (matches ark-vrf prover.prove(blinding_factor))
    let proof = ring_prover.prove(blinding_factor);

    // Serialize to bytes for FFI; TypeScript does serializeProofToOutput for final output format
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| Error::from_reason(format!("Failed to serialize proof: {:?}", e)))?;

    Ok(proof_bytes.into())
}


///





///



///


#[napi]
pub fn compute_ring_commitment(srs_bytes: Buffer, ring_keys_bytes: Buffer) -> Result<Buffer> {
    let srs_bytes = srs_bytes.as_ref();
    let ring_keys_bytes = ring_keys_bytes.as_ref();

    let mut pcs_params: PcsParams = PcsParams::deserialize_uncompressed_unchecked(&mut &srs_bytes[..])
        .map_err(|e| Error::from_reason(format!("Failed to deserialize SRS: {:?}", e)))?;

    const KEY_SIZE: usize = 32;
    let ring_size = ring_keys_bytes.len() / KEY_SIZE;
    let piop_domain_size = piop_domain_size_from_ring_size(ring_size);
    let pcs_domain_size = pcs_domain_size_from_ring_size(ring_size);

    if pcs_params.powers_in_g1.len() < pcs_domain_size || pcs_params.powers_in_g2.len() < 2 {
        return Err(Error::from_reason(format!(
            "SRS too small: need powers_in_g1.len() >= {} and powers_in_g2.len() >= 2, got {} and {}",
            pcs_domain_size,
            pcs_params.powers_in_g1.len(),
            pcs_params.powers_in_g2.len()
        )));
    }
    pcs_params.powers_in_g1.truncate(pcs_domain_size);
    pcs_params.powers_in_g2.truncate(2);

    let padding_point = EdwardsAffine::deserialize_compressed_unchecked(&PADDING_POINT_BYTES[..])
        .expect("Padding point is valid");
    let mut ring_keys = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        let key_bytes = &ring_keys_bytes[i * KEY_SIZE..(i + 1) * KEY_SIZE];
        let is_null = key_bytes.iter().all(|&b| b == 0);
        let key = if is_null {
            padding_point
        } else {
            EdwardsAffine::deserialize_compressed_unchecked(key_bytes).unwrap_or(padding_point)
        };
        ring_keys.push(key);
    }

    // Use Bandersnatch constants (copied from ark-vrf) so commitment matches test vectors
    let domain = Domain::new(piop_domain_size, true);
    let h = bandersnatch_blinding_base();
    let seed = bandersnatch_accumulator_base();
    let padding = bandersnatch_padding();
    let ring_piop_params = RingPiopParams::setup(domain, h, seed, padding);
    let max_ring_size = max_ring_size_from_piop_domain(piop_domain_size);
    let keys_for_index: &[EdwardsAffine] = if ring_keys.len() <= max_ring_size {
        &ring_keys[..]
    } else {
        &ring_keys[..max_ring_size]
    };

    let (_prover_key, verifier_key): (_, RingVerifierKey<Fq, KZG<Bls12_381>>) =
        w3f_ring_proof::index::<_, KZG<Bls12_381>, _>(&pcs_params, &ring_piop_params, keys_for_index);
    let commitment = verifier_key.commitment();

    let mut result = Vec::with_capacity(144);
    commitment.points[0]
        .serialize_compressed(&mut result)
        .map_err(|e| Error::from_reason(format!("Failed to serialize cx: {:?}", e)))?;
    commitment.points[1]
        .serialize_compressed(&mut result)
        .map_err(|e| Error::from_reason(format!("Failed to serialize cy: {:?}", e)))?;
    commitment.ring_selector
        .serialize_compressed(&mut result)
        .map_err(|e| Error::from_reason(format!("Failed to serialize selector: {:?}", e)))?;

    Ok(result.into())
}


///


///





///


#[napi]
pub fn verify_ring_vrf(
    srs_bytes: Buffer,
    proof_bytes: Buffer,
    ring_keys_bytes: Buffer,
    key_commitment_bytes: Buffer,
) -> Result<bool> {
    let srs_bytes = srs_bytes.as_ref();
    let proof_bytes = proof_bytes.as_ref();
    let ring_keys_bytes = ring_keys_bytes.as_ref();
    let key_commitment_bytes = key_commitment_bytes.as_ref();

    let mut pcs_params: PcsParams = PcsParams::deserialize_uncompressed_unchecked(&mut &srs_bytes[..])
        .map_err(|e| Error::from_reason(format!("Failed to deserialize SRS: {:?}", e)))?;

    let proof: W3fRingProof<Fq, KZG<Bls12_381>> =
        W3fRingProof::deserialize_compressed(proof_bytes)
            .map_err(|e| Error::from_reason(format!("Failed to deserialize proof: {:?}", e)))?;

    const KEY_SIZE: usize = 32;
    let ring_size = ring_keys_bytes.len() / KEY_SIZE;
    let piop_domain_size = piop_domain_size_from_ring_size(ring_size);
    let pcs_domain_size = pcs_domain_size_from_ring_size(ring_size);

    if pcs_params.powers_in_g1.len() < pcs_domain_size || pcs_params.powers_in_g2.len() < 2 {
        return Err(Error::from_reason(format!(
            "SRS too small for verification: need powers_in_g1.len() >= {} and powers_in_g2.len() >= 2",
            pcs_domain_size
        )));
    }
    pcs_params.powers_in_g1.truncate(pcs_domain_size);
    pcs_params.powers_in_g2.truncate(2);

    let padding_point = EdwardsAffine::deserialize_compressed_unchecked(&PADDING_POINT_BYTES[..])
        .expect("Padding point is valid");
    let mut ring_keys = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        let key_bytes = &ring_keys_bytes[i * KEY_SIZE..(i + 1) * KEY_SIZE];
        let is_null = key_bytes.iter().all(|&b| b == 0);
        let key = if is_null {
            padding_point
        } else {
            EdwardsAffine::deserialize_compressed_unchecked(key_bytes).unwrap_or(padding_point)
        };
        ring_keys.push(key);
    }

    let key_commitment = EdwardsAffine::deserialize_compressed(key_commitment_bytes)
        .map_err(|e| Error::from_reason(format!("Failed to deserialize key commitment: {:?}", e)))?;

    let domain = Domain::new(piop_domain_size, true);
    let h = bandersnatch_blinding_base();
    let seed = bandersnatch_accumulator_base();
    let padding = bandersnatch_padding();
    let ring_piop_params = RingPiopParams::setup(domain, h, seed, padding);
    let max_ring_size = max_ring_size_from_piop_domain(piop_domain_size);
    let keys_for_index: &[EdwardsAffine] = if ring_keys.len() <= max_ring_size {
        &ring_keys[..]
    } else {
        &ring_keys[..max_ring_size]
    };

    let (_prover_key, verifier_key): (_, RingVerifierKey<Fq, KZG<Bls12_381>>) =
        w3f_ring_proof::index::<_, KZG<Bls12_381>, _>(&pcs_params, &ring_piop_params, keys_for_index);

    let transcript = RingArkTranscript::new(SUITE_ID);
    let ring_verifier = RingVerifier::init(verifier_key, ring_piop_params, transcript);

    let is_valid = ring_verifier.verify(proof, key_commitment);
    Ok(is_valid)
}




#[napi]
pub fn compute_ring_verifier_key(
    srs_bytes: Buffer,
    ring_keys_bytes: Buffer,
) -> Result<Buffer> {
    let srs_bytes = srs_bytes.as_ref();
    let ring_keys_bytes = ring_keys_bytes.as_ref();

    let mut pcs_params: PcsParams =
        PcsParams::deserialize_uncompressed_unchecked(&mut &srs_bytes[..])
            .map_err(|e| Error::from_reason(format!("Failed to deserialize SRS: {:?}", e)))?;

    const KEY_SIZE: usize = 32;
    let ring_size = ring_keys_bytes.len() / KEY_SIZE;
    let piop_domain_size = piop_domain_size_from_ring_size(ring_size);
    let pcs_domain_size = pcs_domain_size_from_ring_size(ring_size);

    if pcs_params.powers_in_g1.len() < pcs_domain_size || pcs_params.powers_in_g2.len() < 2 {
        return Err(Error::from_reason(format!(
            "SRS too small: need powers_in_g1.len() >= {} and powers_in_g2.len() >= 2",
            pcs_domain_size
        )));
    }
    pcs_params.powers_in_g1.truncate(pcs_domain_size);
    pcs_params.powers_in_g2.truncate(2);

    let padding_point = EdwardsAffine::deserialize_compressed_unchecked(&PADDING_POINT_BYTES[..])
        .expect("Padding point is valid");
    let mut ring_keys = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        let key_bytes = &ring_keys_bytes[i * KEY_SIZE..(i + 1) * KEY_SIZE];
        let is_null = key_bytes.iter().all(|&b| b == 0);
        let key = if is_null {
            padding_point
        } else {
            EdwardsAffine::deserialize_compressed_unchecked(key_bytes).unwrap_or(padding_point)
        };
        ring_keys.push(key);
    }

    let domain = Domain::new(piop_domain_size, true);
    let h = bandersnatch_blinding_base();
    let seed = bandersnatch_accumulator_base();
    let padding = bandersnatch_padding();
    let ring_piop_params = RingPiopParams::setup(domain, h, seed, padding);
    let max_ring_size = max_ring_size_from_piop_domain(piop_domain_size);
    let keys_for_index: &[EdwardsAffine] = if ring_keys.len() <= max_ring_size {
        &ring_keys[..]
    } else {
        &ring_keys[..max_ring_size]
    };

    let (_prover_key, verifier_key): (_, RingVerifierKey<Fq, KZG<Bls12_381>>) =
        w3f_ring_proof::index::<_, KZG<Bls12_381>, _>(&pcs_params, &ring_piop_params, keys_for_index);

    let mut out = Vec::new();
    verifier_key
        .serialize_compressed(&mut out)
        .map_err(|e| Error::from_reason(format!("Failed to serialize VerifierKey: {:?}", e)))?;
    Ok(out.into())
}



#[napi]
pub fn verify_ring_vrf_with_key(
    vk_bytes: Buffer,
    proof_bytes: Buffer,
    key_commitment_bytes: Buffer,
    ring_size: u32,
) -> Result<bool> {
    let verifier_key: RingVerifierKey<Fq, KZG<Bls12_381>> =
        RingVerifierKey::deserialize_compressed(vk_bytes.as_ref())
            .map_err(|e| Error::from_reason(format!("Failed to deserialize VerifierKey: {:?}", e)))?;

    let proof: W3fRingProof<Fq, KZG<Bls12_381>> =
        W3fRingProof::deserialize_compressed(proof_bytes.as_ref())
            .map_err(|e| Error::from_reason(format!("Failed to deserialize proof: {:?}", e)))?;

    let key_commitment = EdwardsAffine::deserialize_compressed(key_commitment_bytes.as_ref())
        .map_err(|e| Error::from_reason(format!("Failed to deserialize key commitment: {:?}", e)))?;

    let piop_domain_size = piop_domain_size_from_ring_size(ring_size as usize);
    let domain = Domain::new(piop_domain_size, true);
    let h = bandersnatch_blinding_base();
    let seed = bandersnatch_accumulator_base();
    let padding = bandersnatch_padding();
    let ring_piop_params = RingPiopParams::setup(domain, h, seed, padding);

    let transcript = RingArkTranscript::new(SUITE_ID);
    let ring_verifier = RingVerifier::init(verifier_key, ring_piop_params, transcript);
    Ok(ring_verifier.verify(proof, key_commitment))
}


#[napi(object)]
pub struct RingBatchItem {
    pub proof_bytes: Buffer,
    pub key_commitment_bytes: Buffer,
}


///





#[napi]
pub fn batch_verify_ring_vrf(
    vk_bytes: Buffer,
    ring_size: u32,
    items: Vec<RingBatchItem>,
) -> Result<bool> {
    use crate::batch::vendored::piop::params::PiopParams as VendoredPiopParams;
    use crate::batch::vendored::piop::VerifierKey as VendoredVerifierKey;
    use crate::batch::vendored::ring_verifier::RingVerifier as VendoredRingVerifier;
    use crate::batch::vendored::ArkTranscript as VendoredArkTranscript;
    use crate::batch::vendored::RingProof as VendoredRingProof;
    use ark_ff::One;
    use w3f_pcs::pcs::RawVerifierKey;

    if items.is_empty() {
        return Ok(true);
    }

    let verifier_key: VendoredVerifierKey<Fq, KZG<Bls12_381>> =
        VendoredVerifierKey::deserialize_compressed(vk_bytes.as_ref())
            .map_err(|e| Error::from_reason(format!("Failed to deserialize VerifierKey: {:?}", e)))?;
    let kzg_vk = verifier_key.pcs_raw_vk.prepare();

    let piop_domain_size = piop_domain_size_from_ring_size(ring_size as usize);
    let domain = Domain::new(piop_domain_size, true);
    let ring_piop_params: VendoredPiopParams<Fq, _> = VendoredPiopParams::setup(
        domain,
        bandersnatch_blinding_base(),
        bandersnatch_accumulator_base(),
        bandersnatch_padding(),
    );
    let transcript = VendoredArkTranscript::new(SUITE_ID);
    let ring_verifier = VendoredRingVerifier::init(verifier_key, ring_piop_params, transcript);

    let mut all_openings = Vec::with_capacity(items.len() * 2);
    for item in &items {
        let proof: VendoredRingProof<Fq, KZG<Bls12_381>> =
            VendoredRingProof::deserialize_compressed(item.proof_bytes.as_ref())
                .map_err(|e| Error::from_reason(format!("Failed to deserialize proof: {:?}", e)))?;
        let kc = EdwardsAffine::deserialize_compressed(item.key_commitment_bytes.as_ref())
            .map_err(|e| Error::from_reason(format!("Failed to deserialize key commitment: {:?}", e)))?;
        let [op0, op1] = ring_verifier.openings_for(proof, kc);
        all_openings.push(op0);
        all_openings.push(op1);
    }

    // Fiat-Shamir batching coefficients over all openings; first coefficient is 1.
    let mut t = ark_transcript::Transcript::new_labeled(b"pbnjam_ring_batch_v1".as_slice());
    for op in &all_openings {
        t.append(&op.c);
        t.append(&op.x);
        t.append(&op.y);
        t.append(&op.proof);
    }
    let mut reader = t.challenge(b"coeffs".as_slice());
    let coeffs: Vec<Fq> = (0..all_openings.len())
        .map(|i| {
            if i == 0 {
                Fq::one()
            } else {
                reader.read_reduce::<Fq>()
            }
        })
        .collect();

    let acc = KZG::<Bls12_381>::accumulate(all_openings, &coeffs, &kzg_vk);
    Ok(KZG::<Bls12_381>::verify_accumulated(acc, &kzg_vk))
}
