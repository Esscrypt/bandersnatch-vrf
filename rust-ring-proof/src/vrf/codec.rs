//! Spec §1.4 constants and §1.5 codec. Point enc/dec is added in a later task.
use ark_ed_on_bls12_381_bandersnatch::Fr;
use ark_ff::{BigInteger, PrimeField};

pub const SUITE_ID: &[u8] = b"Bandersnatch-SHA512-ELL2-v1";
pub const CHALLENGE_LEN: usize = 16;
pub const EXPANDED_SCALAR_LEN: usize = 48;

pub const TAG_TINY_VRF: u8 = 0x00;
pub const TAG_THIN_VRF: u8 = 0x01;
pub const TAG_PEDERSEN_VRF: u8 = 0x02;
pub const TAG_NONCE_EXPAND: u8 = 0x10;
pub const TAG_NONCE: u8 = 0x11;
pub const TAG_PEDERSEN_BLINDING: u8 = 0x12;
pub const TAG_POINT_TO_HASH: u8 = 0x20;
pub const TAG_DELINEARIZE: u8 = 0x30;
pub const TAG_CHALLENGE: u8 = 0x40;
pub const TAG_BATCH_VERIFY: u8 = 0x50;
pub const TAG_HASH_TO_CURVE: u8 = 0x60;

/// enc_64: integer as 8-byte little-endian.
pub fn enc_64(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

/// enc_scalar: 32-byte little-endian.
pub fn enc_scalar(s: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let le = s.into_bigint().to_bytes_le();
    out[..le.len()].copy_from_slice(&le);
    out
}

/// dec_scalar: little-endian 32 bytes; None if value >= r.
pub fn dec_scalar(buf: &[u8; 32]) -> Option<Fr> {
    let s = Fr::from_le_bytes_mod_order(buf);
    if &enc_scalar(&s) == buf { Some(s) } else { None }
}

/// dec_scalar_mod: interpret little-endian and reduce mod r.
pub fn dec_scalar_mod(buf: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(buf)
}

use ark_ec::AffineRepr;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsConfig, Fq};
use ark_ff::Field;

pub fn generator() -> EdwardsAffine {
    EdwardsAffine::generator()
}

pub fn enc_point(p: &EdwardsAffine) -> [u8; 32] {
    let mut out = [0u8; 32];
    let y_le = p.y.into_bigint().to_bytes_le();
    out[..y_le.len()].copy_from_slice(&y_le);
    if x_is_negative(&p.x) {
        out[31] |= 0x80;
    }
    out
}

pub fn dec_point(buf: &[u8; 32]) -> Option<EdwardsAffine> {
    let want_neg = (buf[31] & 0x80) != 0;
    let mut y_bytes = *buf;
    y_bytes[31] &= 0x7f;
    let y = Fq::from_le_bytes_mod_order(&y_bytes);
    let mut canon = y.into_bigint().to_bytes_le();
    canon.resize(32, 0);
    if canon != y_bytes {
        return None;
    }
    let p = recover_by_parity(y, want_neg)?;
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(p)
}

/// Spec §1.5 sign of the x-coordinate, matching arkworks TEFlags / CanonicalSerialize:
/// x is "negative" iff it is the larger of {x, -x}, i.e. `x > -x` (upper field half).
fn x_is_negative(x: &Fq) -> bool {
    *x > -*x
}

fn recover_by_parity(y: Fq, want_neg: bool) -> Option<EdwardsAffine> {
    let a = <EdwardsConfig as TECurveConfig>::COEFF_A;
    let d = <EdwardsConfig as TECurveConfig>::COEFF_D;
    let yy = y * y;
    let num = Fq::ONE - yy;
    let den = a - d * yy;
    let xx = num * den.inverse()?;
    let x = xx.sqrt()?;
    let x = if x_is_negative(&x) == want_neg { x } else { -x };
    Some(EdwardsAffine::new_unchecked(x, y))
}

/// Spec §4 blinding base B = hash_to_curve("pedersen-blinding").
pub fn blinding_base() -> ark_ed_on_bls12_381_bandersnatch::EdwardsAffine {
    crate::vrf::hash_to_curve::hash_to_curve(b"pedersen-blinding")
}
