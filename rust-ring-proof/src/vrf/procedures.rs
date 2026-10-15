use crate::vrf::codec::*;
use crate::vrf::transcript::Transcript;
use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::Zero;

pub fn is_valid_point(p: &EdwardsAffine) -> bool {
    !p.is_zero() && p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()
}

pub type Pair = (EdwardsAffine, EdwardsAffine);

pub fn vrf_output(o: &EdwardsAffine, n: usize) -> Vec<u8> {
    let mut t = Transcript::new(SUITE_ID);
    let mut buf = vec![TAG_POINT_TO_HASH];
    buf.extend_from_slice(&enc_point(o));
    t.absorb(&buf);
    t.squeeze(n)
}

pub fn delinearize(io: &[Pair], t: &mut Transcript) -> Pair {
    if io.is_empty() {
        return (EdwardsAffine::zero(), EdwardsAffine::zero());
    }
    t.absorb(&[TAG_DELINEARIZE]);
    let mut im = EdwardsProjective::zero();
    let mut om = EdwardsProjective::zero();
    for (i, (ii, oi)) in io.iter().enumerate() {
        let z = if i == 0 { Fr::from(1u64) } else { dec_scalar_mod(&t.squeeze(CHALLENGE_LEN)) };
        im += *ii * z;
        om += *oi * z;
    }
    (im.into_affine(), om.into_affine())
}

pub fn vrf_transcript(scheme: u8, io: &[Pair], ad: &[u8]) -> (Transcript, Pair) {
    let mut t = Transcript::new(SUITE_ID);
    t.absorb(&[scheme]);
    t.absorb(&enc_64(io.len() as u64));
    for (ii, oi) in io {
        t.absorb(&enc_point(ii));
        t.absorb(&enc_point(oi));
    }
    t.absorb(&enc_64(ad.len() as u64));
    t.absorb(ad);
    let merged = delinearize(io, &mut t.fork());
    (t, merged)
}

pub fn nonce(d: &Fr, mut t: Transcript) -> Fr {
    let mut t_exp = t.fork();
    let mut buf = vec![TAG_NONCE_EXPAND];
    buf.extend_from_slice(&enc_scalar(d));
    t_exp.absorb(&buf);
    let h = t_exp.squeeze(64);
    let mut buf2 = vec![TAG_NONCE];
    buf2.extend_from_slice(&h);
    t.absorb(&buf2);
    dec_scalar_mod(&t.squeeze(EXPANDED_SCALAR_LEN))
}

pub fn challenge(points: &[EdwardsAffine], t: &mut Transcript) -> Fr {
    t.absorb(&[TAG_CHALLENGE]);
    for p in points {
        t.absorb(&enc_point(p));
    }
    dec_scalar_mod(&t.squeeze(CHALLENGE_LEN))
}
