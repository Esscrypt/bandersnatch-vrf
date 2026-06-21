//! Spec §1.6 shared procedures.
use crate::vrf::codec::*;
use crate::vrf::transcript::Transcript;
use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::Zero;

pub fn is_valid_point(p: &EdwardsAffine) -> bool {
    !p.is_zero() && p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()
}

pub type Pair = (EdwardsAffine, EdwardsAffine);

/// §1.6.3 point-to-hash. T = suite_id || PointToHash || enc_point(O); squeeze N.
pub fn vrf_output(o: &EdwardsAffine, n: usize) -> Vec<u8> {
    let mut t = Transcript::new(SUITE_ID);
    let mut buf = vec![TAG_POINT_TO_HASH];
    buf.extend_from_slice(&enc_point(o));
    t.absorb(&buf);
    t.squeeze(n)
}

/// §1.6.4 delinearize. Caller passes a forked transcript. n=0 -> identity pair;
/// z_0 = 1; z_i = dec_scalar_mod(squeeze(CHALLENGE_LEN)) for i>=1.
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

/// §1.6.5 vrf transcript. Returns (T, merged_pair). Delinearize runs on a FORK of T.
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

/// §1.6.6 nonce. Caller passes its transcript BY VALUE (callers pass `t.fork()`).
/// T' (internal fork) does the 64-byte expansion; then Nonce||h is absorbed into the
/// passed-in state and squeezed for EXPANDED_SCALAR_LEN.
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

/// §1.6.7 challenge. Absorbs Challenge tag then each point; squeezes CHALLENGE_LEN.
pub fn challenge(points: &[EdwardsAffine], t: &mut Transcript) -> Fr {
    t.absorb(&[TAG_CHALLENGE]);
    for p in points {
        t.absorb(&enc_point(p));
    }
    dec_scalar_mod(&t.squeeze(CHALLENGE_LEN))
}
