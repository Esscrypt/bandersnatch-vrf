use ark_bls12_381::Bls12_381;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fq, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use w3f_pcs::pcs::kzg::KZG;
use w3f_ring_proof::ring_prover::RingProver;
use w3f_ring_proof::ring_verifier::RingVerifier;
use w3f_ring_proof::ArkTranscript as RingArkTranscript;
use w3f_ring_proof::RingProof as W3fRingProof;
use w3f_ring_proof::VerifierKey as RingVerifierKey;

use crate::padding::{
    deserialize_ring_keys, keys_for_index, pcs_domain_size_from_ring_size,
    piop_domain_size_from_ring_size, ring_piop_params, bandersnatch_accumulator_base,
    bandersnatch_blinding_base, bandersnatch_padding, KEY_SIZE, SUITE_ID, PcsParams,
};
use crate::CoreError;

pub struct RingBatchItemBytes {
    pub proof_bytes: Vec<u8>,
    pub key_commitment_bytes: Vec<u8>,
}

fn deserialize_srs(srs: &[u8]) -> Result<PcsParams, CoreError> {
    PcsParams::deserialize_uncompressed_unchecked(&mut &srs[..])
        .map_err(|e| CoreError::new(format!("Failed to deserialize SRS: {:?}", e)))
}

fn truncate_pcs_params(
    pcs_params: &mut PcsParams,
    ring_size: usize,
    too_small: String,
) -> Result<(), CoreError> {
    let pcs_domain_size = pcs_domain_size_from_ring_size(ring_size);
    if pcs_params.powers_in_g1.len() < pcs_domain_size || pcs_params.powers_in_g2.len() < 2 {
        return Err(CoreError::new(too_small));
    }
    pcs_params.powers_in_g1.truncate(pcs_domain_size);
    pcs_params.powers_in_g2.truncate(2);
    Ok(())
}

pub fn prove_ring_proof(
    srs: &[u8],
    ring_keys: &[u8],
    blinding_factor: &[u8],
    prover_index: u32,
) -> Result<Vec<u8>, CoreError> {
    if ring_keys.len() % KEY_SIZE != 0 {
        return Err(CoreError::new("Invalid ring keys length"));
    }
    let ring_size = ring_keys.len() / KEY_SIZE;

    let mut pcs_params = deserialize_srs(srs)?;
    let piop_domain_size = piop_domain_size_from_ring_size(ring_size);
    let pcs_domain_size = pcs_domain_size_from_ring_size(ring_size);
    let g1_len = pcs_params.powers_in_g1.len();
    let g2_len = pcs_params.powers_in_g2.len();

    truncate_pcs_params(
        &mut pcs_params,
        ring_size,
        format!(
            "SRS too small: need powers_in_g1.len() >= {} and powers_in_g2.len() >= 2, got {} and {}",
            pcs_domain_size, g1_len, g2_len
        ),
    )?;

    let ring_keys = deserialize_ring_keys(ring_keys);

    let blinding_factor = Fr::deserialize_compressed(blinding_factor)
        .map_err(|e| CoreError::new(format!("Failed to deserialize blinding factor: {:?}", e)))?;

    let ring_piop_params = ring_piop_params(piop_domain_size);
    let keys_for_index = keys_for_index(&ring_keys, piop_domain_size);

    let (prover_key, _verifier_key) =
        w3f_ring_proof::index::<_, KZG<Bls12_381>, _>(&pcs_params, &ring_piop_params, keys_for_index);

    let transcript = RingArkTranscript::new(SUITE_ID);
    let ring_prover = RingProver::init(
        prover_key,
        ring_piop_params,
        prover_index as usize,
        transcript,
    );
    let proof = ring_prover.prove(blinding_factor);

    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| CoreError::new(format!("Failed to serialize proof: {:?}", e)))?;

    Ok(proof_bytes)
}

pub fn compute_ring_commitment(srs: &[u8], ring_keys: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut pcs_params = deserialize_srs(srs)?;

    let ring_size = ring_keys.len() / KEY_SIZE;
    let piop_domain_size = piop_domain_size_from_ring_size(ring_size);
    let pcs_domain_size = pcs_domain_size_from_ring_size(ring_size);
    let g1_len = pcs_params.powers_in_g1.len();
    let g2_len = pcs_params.powers_in_g2.len();

    truncate_pcs_params(
        &mut pcs_params,
        ring_size,
        format!(
            "SRS too small: need powers_in_g1.len() >= {} and powers_in_g2.len() >= 2, got {} and {}",
            pcs_domain_size, g1_len, g2_len
        ),
    )?;

    let ring_keys = deserialize_ring_keys(ring_keys);
    let ring_piop_params = ring_piop_params(piop_domain_size);
    let keys_for_index = keys_for_index(&ring_keys, piop_domain_size);

    let (_prover_key, verifier_key): (_, RingVerifierKey<Fq, KZG<Bls12_381>>) =
        w3f_ring_proof::index::<_, KZG<Bls12_381>, _>(&pcs_params, &ring_piop_params, keys_for_index);
    let commitment = verifier_key.commitment();

    let mut result = Vec::with_capacity(144);
    commitment.points[0]
        .serialize_compressed(&mut result)
        .map_err(|e| CoreError::new(format!("Failed to serialize cx: {:?}", e)))?;
    commitment.points[1]
        .serialize_compressed(&mut result)
        .map_err(|e| CoreError::new(format!("Failed to serialize cy: {:?}", e)))?;
    commitment.ring_selector
        .serialize_compressed(&mut result)
        .map_err(|e| CoreError::new(format!("Failed to serialize selector: {:?}", e)))?;

    Ok(result)
}

pub fn verify_ring_vrf(
    srs: &[u8],
    proof: &[u8],
    ring_keys: &[u8],
    key_commitment: &[u8],
) -> Result<bool, CoreError> {
    let mut pcs_params = deserialize_srs(srs)?;

    let proof: W3fRingProof<Fq, KZG<Bls12_381>> = W3fRingProof::deserialize_compressed(proof)
        .map_err(|e| CoreError::new(format!("Failed to deserialize proof: {:?}", e)))?;

    let ring_size = ring_keys.len() / KEY_SIZE;
    let piop_domain_size = piop_domain_size_from_ring_size(ring_size);
    let pcs_domain_size = pcs_domain_size_from_ring_size(ring_size);

    truncate_pcs_params(
        &mut pcs_params,
        ring_size,
        format!(
            "SRS too small for verification: need powers_in_g1.len() >= {} and powers_in_g2.len() >= 2",
            pcs_domain_size
        ),
    )?;

    let ring_keys = deserialize_ring_keys(ring_keys);

    let key_commitment = EdwardsAffine::deserialize_compressed(key_commitment)
        .map_err(|e| CoreError::new(format!("Failed to deserialize key commitment: {:?}", e)))?;

    let ring_piop_params = ring_piop_params(piop_domain_size);
    let keys_for_index = keys_for_index(&ring_keys, piop_domain_size);

    let (_prover_key, verifier_key): (_, RingVerifierKey<Fq, KZG<Bls12_381>>) =
        w3f_ring_proof::index::<_, KZG<Bls12_381>, _>(&pcs_params, &ring_piop_params, keys_for_index);

    let transcript = RingArkTranscript::new(SUITE_ID);
    let ring_verifier = RingVerifier::init(verifier_key, ring_piop_params, transcript);

    Ok(ring_verifier.verify(proof, key_commitment))
}

pub fn compute_ring_verifier_key(srs: &[u8], ring_keys: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut pcs_params = deserialize_srs(srs)?;

    let ring_size = ring_keys.len() / KEY_SIZE;
    let piop_domain_size = piop_domain_size_from_ring_size(ring_size);
    let pcs_domain_size = pcs_domain_size_from_ring_size(ring_size);

    truncate_pcs_params(
        &mut pcs_params,
        ring_size,
        format!(
            "SRS too small: need powers_in_g1.len() >= {} and powers_in_g2.len() >= 2",
            pcs_domain_size
        ),
    )?;

    let ring_keys = deserialize_ring_keys(ring_keys);
    let ring_piop_params = ring_piop_params(piop_domain_size);
    let keys_for_index = keys_for_index(&ring_keys, piop_domain_size);

    let (_prover_key, verifier_key): (_, RingVerifierKey<Fq, KZG<Bls12_381>>) =
        w3f_ring_proof::index::<_, KZG<Bls12_381>, _>(&pcs_params, &ring_piop_params, keys_for_index);

    let mut out = Vec::new();
    verifier_key
        .serialize_compressed(&mut out)
        .map_err(|e| CoreError::new(format!("Failed to serialize VerifierKey: {:?}", e)))?;
    Ok(out)
}

pub fn verify_ring_vrf_with_key(
    vk: &[u8],
    proof: &[u8],
    key_commitment: &[u8],
    ring_size: u32,
) -> Result<bool, CoreError> {
    let verifier_key: RingVerifierKey<Fq, KZG<Bls12_381>> =
        RingVerifierKey::deserialize_compressed(vk)
            .map_err(|e| CoreError::new(format!("Failed to deserialize VerifierKey: {:?}", e)))?;

    let proof: W3fRingProof<Fq, KZG<Bls12_381>> = W3fRingProof::deserialize_compressed(proof)
        .map_err(|e| CoreError::new(format!("Failed to deserialize proof: {:?}", e)))?;

    let key_commitment = EdwardsAffine::deserialize_compressed(key_commitment)
        .map_err(|e| CoreError::new(format!("Failed to deserialize key commitment: {:?}", e)))?;

    let piop_domain_size = piop_domain_size_from_ring_size(ring_size as usize);
    let ring_piop_params = ring_piop_params(piop_domain_size);

    let transcript = RingArkTranscript::new(SUITE_ID);
    let ring_verifier = RingVerifier::init(verifier_key, ring_piop_params, transcript);
    Ok(ring_verifier.verify(proof, key_commitment))
}

pub fn batch_verify_ring_vrf(
    vk: &[u8],
    ring_size: u32,
    items: &[RingBatchItemBytes],
) -> Result<bool, CoreError> {
    use crate::batch::vendored::piop::params::PiopParams as VendoredPiopParams;
    use crate::batch::vendored::piop::VerifierKey as VendoredVerifierKey;
    use crate::batch::vendored::ring_verifier::RingVerifier as VendoredRingVerifier;
    use crate::batch::vendored::ArkTranscript as VendoredArkTranscript;
    use crate::batch::vendored::RingProof as VendoredRingProof;
    use ark_ff::One;
    use w3f_pcs::pcs::RawVerifierKey;
    use w3f_ring_proof::Domain;

    if items.is_empty() {
        return Ok(true);
    }

    let verifier_key: VendoredVerifierKey<Fq, KZG<Bls12_381>> =
        VendoredVerifierKey::deserialize_compressed(vk)
            .map_err(|e| CoreError::new(format!("Failed to deserialize VerifierKey: {:?}", e)))?;
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
    for item in items {
        let proof: VendoredRingProof<Fq, KZG<Bls12_381>> =
            VendoredRingProof::deserialize_compressed(&mut &item.proof_bytes[..])
                .map_err(|e| CoreError::new(format!("Failed to deserialize proof: {:?}", e)))?;
        let kc = EdwardsAffine::deserialize_compressed(&mut &item.key_commitment_bytes[..])
            .map_err(|e| CoreError::new(format!("Failed to deserialize key commitment: {:?}", e)))?;
        let [op0, op1] = ring_verifier.openings_for(proof, kc);
        all_openings.push(op0);
        all_openings.push(op1);
    }

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
