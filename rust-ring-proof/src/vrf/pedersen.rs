use crate::vrf::codec::{blinding_base, enc_point, generator, TAG_PEDERSEN_BLINDING, TAG_PEDERSEN_VRF};
use crate::vrf::procedures::{challenge, is_valid_point, nonce, vrf_transcript, Pair};
use crate::vrf::transcript::Transcript;
use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fr};

#[derive(Clone)]
pub struct Proof {
    pub pk_com: EdwardsAffine,
    pub r: EdwardsAffine,
    pub ok: EdwardsAffine,
    pub s: Fr,
    pub sb: Fr,
}

fn blinding(x: &Fr, mut t: Transcript) -> Fr {
    t.absorb(&[TAG_PEDERSEN_BLINDING]);
    nonce(x, t)
}

pub fn prove(x: &Fr, io: &[Pair], ad: &[u8]) -> (Proof, Fr) {
    let g = generator();
    let bb = blinding_base();
    let (t, (im, _om)) = vrf_transcript(TAG_PEDERSEN_VRF, io, ad);
    let b = blinding(x, t.fork());
    let pk_com = ((g * x) + (bb * b)).into_affine();
    let mut t = t;
    t.absorb(&enc_point(&pk_com));
    let k = nonce(x, t.fork());
    let kb = nonce(&b, t.fork());
    let r = ((g * k) + (bb * kb)).into_affine();
    let ok = (im * k).into_affine();
    let c = challenge(&[r, ok], &mut t);
    let s = k + c * x;
    let sb = kb + c * b;
    (Proof { pk_com, r, ok, s, sb }, b)
}

pub fn verify(io: &[Pair], ad: &[u8], p: &Proof) -> bool {
    if !is_valid_point(&p.pk_com) || !is_valid_point(&p.r) || !is_valid_point(&p.ok) || io.iter().any(|(ii, oi)| !is_valid_point(ii) || !is_valid_point(oi)) {
        return false;
    }
    let g = generator();
    let bb = blinding_base();
    let (t, (im, om)) = vrf_transcript(TAG_PEDERSEN_VRF, io, ad);
    let mut t = t;
    t.absorb(&enc_point(&p.pk_com));
    let c = challenge(&[p.r, p.ok], &mut t);
    let lhs0 = (p.ok + (om * c).into_affine()).into_affine();
    let rhs0 = (im * p.s).into_affine();
    let lhs1 = (p.r + (p.pk_com * c).into_affine()).into_affine();
    let rhs1 = ((g * p.s) + (bb * p.sb)).into_affine();
    lhs0 == rhs0 && lhs1 == rhs1
}

pub fn unblind(pk_com: &EdwardsAffine, y: &EdwardsAffine, b: &Fr) -> bool {
    (*y + (blinding_base() * b).into_affine()).into_affine() == *pk_com
}

pub fn batch_verify(items: &[(Vec<Pair>, Vec<u8>, Proof)]) -> bool {
    items.iter().all(|(io, ad, p)| verify(io, ad, p))
}
