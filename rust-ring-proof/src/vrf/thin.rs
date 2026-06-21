//! Spec §3 Thin VRF. Proof = (R, s); R stores the nonce commitment (batch-verifiable).
use crate::vrf::codec::{generator, TAG_THIN_VRF};
use crate::vrf::procedures::{challenge, is_valid_point, nonce, vrf_transcript, Pair};
use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fr};

fn with_schnorr(y: EdwardsAffine, io: &[Pair]) -> Vec<Pair> {
    let mut v = Vec::with_capacity(io.len() + 1);
    v.push((generator(), y));
    v.extend_from_slice(io);
    v
}

pub fn prove(x: &Fr, io: &[Pair], ad: &[u8]) -> (EdwardsAffine, Fr) {
    let y = (generator() * x).into_affine();
    let (t, (im, _om)) = vrf_transcript(TAG_THIN_VRF, &with_schnorr(y, io), ad);
    let k = nonce(x, t.fork());
    let r = (im * k).into_affine();
    let mut tc = t;
    let c = challenge(&[r], &mut tc);
    let s = k + c * x;
    (r, s)
}

pub fn verify(y: &EdwardsAffine, io: &[Pair], ad: &[u8], r: &EdwardsAffine, s: &Fr) -> bool {
    if !is_valid_point(y) || !is_valid_point(r) || io.iter().any(|(ii, oi)| !is_valid_point(ii) || !is_valid_point(oi)) {
        return false;
    }
    let (t, (im, om)) = vrf_transcript(TAG_THIN_VRF, &with_schnorr(*y, io), ad);
    let mut tc = t;
    let c = challenge(&[*r], &mut tc);
    (im * s).into_affine() == (*r + (om * c).into_affine()).into_affine()
}

pub type ThinItem = (EdwardsAffine, Vec<Pair>, Vec<u8>, EdwardsAffine, Fr);

pub fn batch_verify(items: &[ThinItem]) -> bool {
    items.iter().all(|(y, io, ad, r, s)| verify(y, io, ad, r, s))
}
