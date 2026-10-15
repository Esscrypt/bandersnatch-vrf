use ark_ed_on_bls12_381_bandersnatch::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::{
    ietf::{Proof as IetfProof, Prover as IetfProver, Verifier as IetfVerifier},
    suites::bandersnatch::BandersnatchSha512Ell2,
    Input, Output, Public, Secret,
};

use crate::CoreError;

const GAMMA_LEN: usize = 32;
const PROOF_TOTAL_LEN: usize = 96;

pub fn prove_ietf_vrf(
    secret_key: &[u8],
    input: &[u8],
    aux: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let scalar = Fr::deserialize_compressed(secret_key)
        .map_err(|e| CoreError::new(format!("Failed to deserialize secret key: {:?}", e)))?;

    let secret = Secret::<BandersnatchSha512Ell2>::from_scalar(scalar);

    let input = Input::<BandersnatchSha512Ell2>::new(input)
        .ok_or_else(|| CoreError::new("Failed to hash input to curve"))?;

    let output = secret.output(input);

    let proof: IetfProof<BandersnatchSha512Ell2> = secret.prove(input, output, aux);

    let mut result = Vec::with_capacity(PROOF_TOTAL_LEN);
    output
        .0
        .serialize_compressed(&mut result)
        .map_err(|e| CoreError::new(format!("Failed to serialize gamma: {:?}", e)))?;
    proof
        .serialize_compressed(&mut result)
        .map_err(|e| CoreError::new(format!("Failed to serialize proof: {:?}", e)))?;

    Ok(result)
}

pub fn verify_ietf_vrf(
    public_key: &[u8],
    input: &[u8],
    proof: &[u8],
    aux: &[u8],
) -> Result<bool, CoreError> {
    if proof.len() != PROOF_TOTAL_LEN {
        return Err(CoreError::new(format!(
            "Invalid proof length: expected {} bytes, got {}",
            PROOF_TOTAL_LEN,
            proof.len()
        )));
    }

    let public = Public::<BandersnatchSha512Ell2>::deserialize_compressed(public_key)
        .map_err(|e| CoreError::new(format!("Failed to deserialize public key: {:?}", e)))?;

    let input = Input::<BandersnatchSha512Ell2>::new(input)
        .ok_or_else(|| CoreError::new("Failed to hash input to curve"))?;

    let output = Output::<BandersnatchSha512Ell2>::deserialize_compressed(&proof[..GAMMA_LEN])
        .map_err(|e| CoreError::new(format!("Failed to deserialize gamma: {:?}", e)))?;

    let proof = IetfProof::<BandersnatchSha512Ell2>::deserialize_compressed(&mut &proof[GAMMA_LEN..])
        .map_err(|e| CoreError::new(format!("Failed to deserialize proof (c||s): {:?}", e)))?;

    Ok(public.verify(input, output, aux, &proof).is_ok())
}
