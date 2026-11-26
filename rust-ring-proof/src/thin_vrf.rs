use crate::vrf::{codec, hash_to_curve, procedures, thin};
use ark_ec::CurveGroup;
use napi::bindgen_prelude::*;
use napi_derive::napi;

const POINT_LEN: usize = 32;
const PROOF_LEN: usize = 96;

#[napi]
pub fn prove_thin_vrf(
    secret_key_bytes: Buffer,
    alpha_bytes: Buffer,
    ad_bytes: Buffer,
) -> Result<Buffer> {
    let sk: [u8; 32] = secret_key_bytes
        .as_ref()
        .try_into()
        .map_err(|_| Error::from_reason("secret key must be 32 bytes"))?;
    let x = codec::dec_scalar(&sk)
        .ok_or_else(|| Error::from_reason("secret key is not a canonical scalar"))?;

    let i = hash_to_curve::hash_to_curve(alpha_bytes.as_ref());
    let o = (i * x).into_affine();
    let (r, s) = thin::prove(&x, &[(i, o)], ad_bytes.as_ref());

    let mut out = Vec::with_capacity(PROOF_LEN);
    out.extend_from_slice(&codec::enc_point(&o));
    out.extend_from_slice(&codec::enc_point(&r));
    out.extend_from_slice(&codec::enc_scalar(&s));
    Ok(Buffer::from(out))
}

/// Verifies a 96-octet graypaper signature, `O || R || s`.
///
/// The standalone VRF specification defines the proof as `(R, s)` and takes the
/// output point `O` as a separate input/output pair; the graypaper fixes the
/// concatenation order (`graypaper#593`). This splits the envelope and defers to
/// [`verify_thin_vrf_parts`].
#[napi]
pub fn verify_thin_vrf(
    public_key_bytes: Buffer,
    alpha_bytes: Buffer,
    signature_bytes: Buffer,
    ad_bytes: Buffer,
) -> Result<bool> {
    if signature_bytes.len() != PROOF_LEN {
        return Err(Error::from_reason(
            "signature must be 96 bytes (O || R || s)",
        ));
    }
    let o = Buffer::from(signature_bytes[..32].to_vec());
    let r = Buffer::from(signature_bytes[32..64].to_vec());
    let s = Buffer::from(signature_bytes[64..].to_vec());
    verify_thin_vrf_parts(public_key_bytes, alpha_bytes, o, r, s, ad_bytes)
}

/// Verifies a Thin VRF proof in the specification's own shape: the output point
/// `O`, the proof point `R`, the response `s`, and the input/output pairs.
#[napi]
pub fn verify_thin_vrf_parts(
    public_key_bytes: Buffer,
    alpha_bytes: Buffer,
    output_point_bytes: Buffer,
    proof_r_bytes: Buffer,
    proof_s_bytes: Buffer,
    ad_bytes: Buffer,
) -> Result<bool> {
    let pk: [u8; 32] = public_key_bytes
        .as_ref()
        .try_into()
        .map_err(|_| Error::from_reason("public key must be 32 bytes"))?;
    let y = codec::dec_point(&pk).ok_or_else(|| Error::from_reason("invalid public key"))?;

    let o_bytes: [u8; 32] = output_point_bytes
        .as_ref()
        .try_into()
        .map_err(|_| Error::from_reason("output point must be 32 bytes"))?;
    let r_bytes: [u8; 32] = proof_r_bytes
        .as_ref()
        .try_into()
        .map_err(|_| Error::from_reason("proof r must be 32 bytes"))?;
    let s_bytes: [u8; 32] = proof_s_bytes
        .as_ref()
        .try_into()
        .map_err(|_| Error::from_reason("proof s must be 32 bytes"))?;

    let Some(o) = codec::dec_point(&o_bytes) else {
        return Ok(false);
    };
    let Some(r) = codec::dec_point(&r_bytes) else {
        return Ok(false);
    };
    let Some(s) = codec::dec_scalar(&s_bytes) else {
        return Ok(false);
    };

    let i = hash_to_curve::hash_to_curve(alpha_bytes.as_ref());
    Ok(thin::verify(&y, &[(i, o)], ad_bytes.as_ref(), &r, &s))
}

#[napi]
pub fn thin_vrf_output(output_point_bytes: Buffer) -> Result<Buffer> {
    let p: [u8; POINT_LEN] = output_point_bytes
        .as_ref()
        .try_into()
        .map_err(|_| Error::from_reason("output point must be 32 bytes"))?;
    let gamma = codec::dec_point(&p).ok_or_else(|| Error::from_reason("invalid output point"))?;
    Ok(Buffer::from(procedures::vrf_output(&gamma, 32)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    #[test]
    fn proof_format_matches_spec_vectors() {
        let vectors = crate::vrf::tests::load_vectors("thin");
        let v = &vectors[0];
        let sk: [u8; 32] = hexd(&v.sk).try_into().unwrap();
        let alpha = hexd(&v.alpha);
        let ad = hexd(&v.ad);

        let x = codec::dec_scalar(&sk).unwrap();
        let i = crate::vrf::hash_to_curve::hash_to_curve(&alpha);
        let o = (i * x).into_affine();
        let (r, s) = thin::prove(&x, &[(i, o)], &ad);

        assert_eq!(hex::encode(codec::enc_point(&o)), v.gamma, "output point");
        assert_eq!(hex::encode(codec::enc_point(&r)), v.proof_r, "proof_r");
        assert_eq!(hex::encode(codec::enc_scalar(&s)), v.proof_s, "proof_s");
    }

    #[test]
    fn output_hash_matches_spec_beta() {
        let vectors = crate::vrf::tests::load_vectors("thin");
        let v = &vectors[0];
        let gamma = codec::dec_point(&hexd(&v.gamma).try_into().unwrap()).unwrap();
        assert_eq!(
            hex::encode(procedures::vrf_output(&gamma, 32)),
            v.beta,
            "beta"
        );
    }
}

