use crate::vrf::codec::{generator, CHALLENGE_LEN, TAG_TINY_VRF};
use crate::vrf::procedures::{challenge, is_valid_point, nonce, vrf_transcript, Pair};
use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fr};
use ark_ff::{BigInteger, PrimeField};

fn with_schnorr(y: EdwardsAffine, io: &[Pair]) -> Vec<Pair> {
    let mut v = Vec::with_capacity(io.len() + 1);
    v.push((generator(), y));
    v.extend_from_slice(io);
    v
}

pub fn prove(x: &Fr, io: &[Pair], ad: &[u8]) -> (Vec<u8>, Fr) {
    let y = (generator() * x).into_affine();
    let (t, (im, _om)) = vrf_transcript(TAG_TINY_VRF, &with_schnorr(y, io), ad);
    let k = nonce(x, t.fork());
    let r = (im * k).into_affine();
    let mut tc = t;
    let c = challenge(&[r], &mut tc);
    let s = k + c * x;
    (c_to_bytes(&c), s)
}

pub fn verify(y: &EdwardsAffine, io: &[Pair], ad: &[u8], c_bytes: &[u8], s: &Fr) -> bool {
    if c_bytes.len() != CHALLENGE_LEN {
        return false;
    }
    if !is_valid_point(y) || io.iter().any(|(ii, oi)| !is_valid_point(ii) || !is_valid_point(oi)) {
        return false;
    }
    let (t, (im, om)) = vrf_transcript(TAG_TINY_VRF, &with_schnorr(*y, io), ad);
    let c = bytes_to_c(c_bytes);
    let r = (im * s - om * c).into_affine();
    let mut tc = t;
    let c2 = challenge(&[r], &mut tc);
    c2 == c
}

fn c_to_bytes(c: &Fr) -> Vec<u8> {
    c.into_bigint().to_bytes_le()[..CHALLENGE_LEN].to_vec()
}

fn bytes_to_c(b: &[u8]) -> Fr {
    crate::vrf::codec::dec_scalar_mod(b)
}
