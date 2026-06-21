//! Spec A.2 hash-to-curve: RFC-9380 expand_message_xmd(SHA-512) + Elligator2 RO.
//! Ported from packages/bandersnatch-vrf/src/crypto/elligator2.ts.
use crate::vrf::codec::{SUITE_ID, TAG_HASH_TO_CURVE};
use ark_ec::twisted_edwards::{MontCurveConfig, TECurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsConfig, Fq};
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use sha2::{Digest, Sha512};

const SHA512_OUTPUT_LEN: usize = 64;
/// len_per_base_elem = ceil((MODULUS_BIT_SIZE + SEC_PARAM) / 8) = ceil((255 + 128) / 8) = 48.
const LEN_PER_BASE_ELEM: usize = 48;

pub fn hash_to_curve(msg: &[u8]) -> EdwardsAffine {
    let mut dst = SUITE_ID.to_vec();
    dst.push(TAG_HASH_TO_CURVE);

    let [u0, u1] = hash_to_field(msg, &dst);
    let p0 = elligator2_map(u0);
    let p1 = elligator2_map(u1);
    let sum = (p0 + p1).into_affine();
    clear_cofactor(sum)
}

/// RFC-9380 §5.2 hash_to_field for two base-field elements (arkworks DefaultFieldHasher).
fn hash_to_field(msg: &[u8], dst: &[u8]) -> [Fq; 2] {
    let len_in_bytes = 2 * LEN_PER_BASE_ELEM;
    let uniform = expand_message_xmd(msg, dst, len_in_bytes);
    let u0 = Fq::from_be_bytes_mod_order(&uniform[0..LEN_PER_BASE_ELEM]);
    let u1 = Fq::from_be_bytes_mod_order(&uniform[LEN_PER_BASE_ELEM..2 * LEN_PER_BASE_ELEM]);
    [u0, u1]
}

/// RFC-9380 §5.3.1 expand_message_xmd with SHA-512.
/// Z_pad uses arkworks block_size = len_per_base_elem (48), matching DefaultFieldHasher.
fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    let dst_prime = build_dst_prime(dst);

    let ell = len_in_bytes.div_ceil(SHA512_OUTPUT_LEN);
    assert!(ell <= 255, "expand_message_xmd: too much output requested");
    assert!(len_in_bytes < (1 << 16), "expand_message_xmd: len too large");

    let z_pad = [0u8; LEN_PER_BASE_ELEM];
    let l_i_b_str = (len_in_bytes as u16).to_be_bytes();

    let mut h = Sha512::new();
    h.update(z_pad);
    h.update(msg);
    h.update(l_i_b_str);
    h.update([0u8]);
    h.update(&dst_prime);
    let b_0 = h.finalize();

    let mut h = Sha512::new();
    h.update(b_0);
    h.update([1u8]);
    h.update(&dst_prime);
    let mut b_prev = h.finalize();

    let mut out = Vec::with_capacity(len_in_bytes);
    out.extend_from_slice(&b_prev);

    for i in 2..=ell {
        let mut h = Sha512::new();
        let xored: Vec<u8> = b_0.iter().zip(b_prev.iter()).map(|(l, r)| l ^ r).collect();
        h.update(&xored);
        h.update([i as u8]);
        h.update(&dst_prime);
        b_prev = h.finalize();
        out.extend_from_slice(&b_prev);
    }

    out.truncate(len_in_bytes);
    out
}

/// DST_prime = DST ‖ I2OSP(len(DST), 1), with RFC-9380 §5.3.3 oversize handling.
fn build_dst_prime(dst: &[u8]) -> Vec<u8> {
    let normalized: Vec<u8> = if dst.len() > 255 {
        let mut h = Sha512::new();
        h.update(b"H2C-OVERSIZE-DST-");
        h.update(dst);
        h.finalize().to_vec()
    } else {
        dst.to_vec()
    };
    let len = normalized.len() as u8;
    let mut out = normalized;
    out.push(len);
    out
}

/// RFC-9380 §6.8.2 Elligator2 map for the Bandersnatch twisted Edwards curve.
/// Mirrors arkworks `Elligator2Map::map_to_curve`.
fn elligator2_map(element: Fq) -> EdwardsAffine {
    let k = <EdwardsConfig as MontCurveConfig>::COEFF_B;
    let j_on_k = <EdwardsConfig as ark_ec::hashing::curve_maps::elligator2::Elligator2Config>::COEFF_A_OVER_COEFF_B;
    let ksq_inv = <EdwardsConfig as ark_ec::hashing::curve_maps::elligator2::Elligator2Config>::ONE_OVER_COEFF_B_SQUARE;
    let z = <EdwardsConfig as ark_ec::hashing::curve_maps::elligator2::Elligator2Config>::Z;

    let den_1 = Fq::one() + z * element.square();
    let x1 = -j_on_k / (if den_1.is_zero() { Fq::one() } else { den_1 });
    let x1sq = x1.square();
    let x1cb = x1sq * x1;
    let gx1 = x1cb + j_on_k * x1sq + x1 * ksq_inv;

    let x2 = -x1 - j_on_k;
    let x2sq = x2.square();
    let x2cb = x2sq * x2;
    let gx2 = x2cb + j_on_k * x2sq + x2 * ksq_inv;

    let (x, mut y, sgn0) = if gx1.legendre().is_qr() {
        (x1, gx1.sqrt().expect("gx1 is a QR"), true)
    } else {
        (x2, gx2.sqrt().expect("gx2 is a QR"), false)
    };

    if parity(&y) != sgn0 {
        y = -y;
    }

    let s = x * k;
    let t = y * k;

    let tv1 = s + Fq::one();
    let tv2 = tv1 * t;
    let (v, w) = if tv2.is_zero() {
        (Fq::zero(), Fq::one())
    } else {
        let tv2_inv = tv2.inverse().expect("nonzero element has inverse");
        let v = tv2_inv * tv1 * s;
        let w = tv2_inv * t * (s - Fq::one());
        (v, w)
    };

    EdwardsAffine::new_unchecked(v, w)
}

/// RFC-9380 §4.1 sign-of-field: least significant bit of the canonical representation.
fn parity(element: &Fq) -> bool {
    element.into_bigint().is_odd()
}

/// arkworks default clear_cofactor: multiply by the cofactor (4 for Bandersnatch).
fn clear_cofactor(p: EdwardsAffine) -> EdwardsAffine {
    p.mul_by_cofactor()
}
