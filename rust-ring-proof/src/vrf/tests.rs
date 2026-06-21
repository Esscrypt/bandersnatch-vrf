//! Vector-driven tests for the self-contained bandersnatch VRF.
use crate::vrf::codec;
use ark_ed_on_bls12_381_bandersnatch::Fr;
use ark_ff::{One, Zero};

#[test]
fn codec_constants_and_scalars() {
    assert_eq!(codec::SUITE_ID, b"Bandersnatch-SHA512-ELL2-v1");
    assert_eq!(codec::SUITE_ID.len(), 27);
    assert_eq!(codec::CHALLENGE_LEN, 16);
    assert_eq!(codec::EXPANDED_SCALAR_LEN, 48);

    assert_eq!(codec::enc_64(1), [1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(codec::enc_64(0x0102), [0x02, 0x01, 0, 0, 0, 0, 0, 0]);

    let s = Fr::one();
    let bytes = codec::enc_scalar(&s);
    assert_eq!(bytes.len(), 32);
    assert_eq!(codec::dec_scalar(&bytes).unwrap(), s);
    let mut over = [0xffu8; 32];
    assert!(codec::dec_scalar(&over).is_none()); // all-ones >= r
    over.fill(0);
    assert_eq!(codec::dec_scalar(&over).unwrap(), Fr::zero());

    let _ = codec::dec_scalar_mod(&[0xffu8; 48]);
}

use crate::vrf::codec::{dec_point, enc_point, generator};
use ark_ec::{AffineRepr, CurveGroup};

pub fn hexd(s: &str) -> Vec<u8> { hex::decode(s).expect("hex") }

#[test]
fn codec_point_roundtrip_and_vector_pk() {
    let sk = hexd("c9922b7a9849b9928e15c655dd2f22ceef737cc355024f43d4b04bf4398c270d");
    let pk_hex = "5a538209ff1fc7b1c9c8e1da05b3e169acf10a8b1591b3af029fe4eede0bbc71";
    let sk_arr: [u8; 32] = sk.try_into().unwrap();
    let x = crate::vrf::codec::dec_scalar(&sk_arr).unwrap();
    let y_pub = (generator() * x).into_affine();
    assert_eq!(hex::encode(enc_point(&y_pub)), pk_hex, "pk vector (sign convention)");

    let dec = dec_point(&enc_point(&y_pub)).unwrap();
    assert_eq!(dec, y_pub, "point round-trip");

    assert!(generator().is_on_curve() && generator().is_in_correct_subgroup_assuming_on_curve());

    let mut junk = [0xAAu8; 32];
    junk[31] &= 0x7f;
    let _ = dec_point(&junk);
}

use crate::vrf::transcript::Transcript;

#[test]
fn transcript_squeeze_is_counter_xof() {
    let mut t1 = Transcript::new(codec::SUITE_ID);
    t1.absorb(b"hello");
    let full = t1.squeeze(96);

    let mut t2 = Transcript::new(codec::SUITE_ID);
    t2.absorb(b"hello");
    let mut part = t2.squeeze(64);
    part.extend_from_slice(&t2.squeeze(32));
    assert_eq!(full, part);

    let mut a = Transcript::new(codec::SUITE_ID);
    a.absorb(b"x");
    let b = a.fork();
    assert_eq!(a.squeeze(32), b.fork().squeeze(32));

    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(codec::SUITE_ID);
    h.update(b"hello");
    let seed = h.finalize();
    let mut h0 = Sha512::new();
    h0.update(&seed);
    h0.update(codec::enc_64(0));
    let block0 = h0.finalize();
    let mut t3 = Transcript::new(codec::SUITE_ID);
    t3.absorb(b"hello");
    assert_eq!(t3.squeeze(64), block0.as_slice());
}

use crate::vrf::hash_to_curve::hash_to_curve;

#[test]
fn hash_to_curve_matches_vectors() {
    // tiny/thin/pedersen vector-1: alpha = "" -> h
    let h0 = hash_to_curve(b"");
    assert_eq!(hex::encode(crate::vrf::codec::enc_point(&h0)),
        "f508a4e84812ee3dce73ef72bb9064308128384b4801f81ef8616a7dffc486bc", "alpha=empty");
    // tiny vector-2: alpha = "0a" -> h
    let h = hash_to_curve(&hexd("0a"));
    assert_eq!(hex::encode(crate::vrf::codec::enc_point(&h)),
        "8ec04d55a790d47cd32c5062cb44517f164515dac88a8ea6d972db1a7da08abf", "alpha=0a");
}

#[test]
fn blinding_base_is_valid_subgroup_point() {
    use ark_ec::AffineRepr;
    let b = crate::vrf::codec::blinding_base();
    assert!(b.is_on_curve() && b.is_in_correct_subgroup_assuming_on_curve());
    assert_ne!(b, crate::vrf::codec::generator());
}

#[test]
fn vrf_output_matches_vector_beta() {
    use crate::vrf::procedures::vrf_output;
    use crate::vrf::codec::dec_point;
    // tiny vector-1: gamma (O) -> beta (32 bytes).
    let gamma = dec_point(&hexd("54421f7ffc399872f1cb868efbb7eef4034178f1e369cebfb964ca61e4f3f256").try_into().unwrap()).unwrap();
    let beta = vrf_output(&gamma, 32);
    assert_eq!(hex::encode(&beta),
        "7b89f2aba6af7474694f24f75adf48336e00dcc8f3ac889ef4daa53c859497a6");
}

use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
pub struct Vector {
    pub sk: String, pub pk: String, pub alpha: String, pub ad: String,
    pub h: String, pub gamma: String, pub beta: String,
    #[serde(default)] pub proof_c: String,
    #[serde(default)] pub proof_s: String,
    #[serde(default)] pub proof_r: String,
    #[serde(default)] pub blinding: String,
    #[serde(default)] pub proof_pk_com: String,
    #[serde(default)] pub proof_ok: String,
    #[serde(default)] pub proof_sb: String,
}

pub fn load_vectors(name: &str) -> Vec<Vector> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..3 { p.pop(); }
    p.push("submodules/bandersnatch-vrf-spec/assets/vectors");
    p.push(format!("bandersnatch_sha-512_ell2_{name}.json"));
    let data = std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("read {:?}", p));
    serde_json::from_str(&data).expect("parse vectors")
}

#[test]
fn tiny_vrf_matches_all_vectors() {
    use crate::vrf::{codec, tiny};
    use ark_ec::CurveGroup;
    for v in load_vectors("tiny") {
        let x = codec::dec_scalar(&hexd(&v.sk).try_into().unwrap()).unwrap();
        let i = crate::vrf::hash_to_curve::hash_to_curve(&hexd(&v.alpha));
        assert_eq!(hex::encode(codec::enc_point(&i)), v.h, "h mismatch");
        let o = (i * x).into_affine();
        let ad = hexd(&v.ad);
        let (c, s) = tiny::prove(&x, &[(i, o)], &ad);
        assert_eq!(hex::encode(&c), v.proof_c, "proof_c");
        assert_eq!(hex::encode(codec::enc_scalar(&s)), v.proof_s, "proof_s");
        let y = codec::dec_point(&hexd(&v.pk).try_into().unwrap()).unwrap();
        let og = codec::dec_point(&hexd(&v.gamma).try_into().unwrap()).unwrap();
        assert!(tiny::verify(&y, &[(i, og)], &ad, &c, &s), "verify");
        let bad = s + ark_ed_on_bls12_381_bandersnatch::Fr::from(1u64);
        assert!(!tiny::verify(&y, &[(i, og)], &ad, &c, &bad), "verify rejects bad s");
    }
}

#[test]
fn thin_vrf_matches_all_vectors() {
    use crate::vrf::{codec, thin};
    use ark_ec::CurveGroup;
    let mut all = Vec::new();
    for v in load_vectors("thin") {
        let x = codec::dec_scalar(&hexd(&v.sk).try_into().unwrap()).unwrap();
        let i = crate::vrf::hash_to_curve::hash_to_curve(&hexd(&v.alpha));
        let o = (i * x).into_affine();
        let ad = hexd(&v.ad);
        let (r, s) = thin::prove(&x, &[(i, o)], &ad);
        assert_eq!(hex::encode(codec::enc_point(&r)), v.proof_r, "proof_r");
        assert_eq!(hex::encode(codec::enc_scalar(&s)), v.proof_s, "proof_s");
        let y = codec::dec_point(&hexd(&v.pk).try_into().unwrap()).unwrap();
        assert!(thin::verify(&y, &[(i, o)], &ad, &r, &s), "verify");
        all.push((y, vec![(i, o)], ad, r, s));
    }
    assert!(thin::batch_verify(&all), "batch verify accepts");
    let mut bad = all.clone();
    bad[0].4 = bad[0].4 + ark_ed_on_bls12_381_bandersnatch::Fr::from(1u64);
    assert!(!thin::batch_verify(&bad), "batch verify rejects corrupted");
}

#[test]
fn pedersen_vrf_matches_all_vectors() {
    use crate::vrf::{codec, pedersen};
    use ark_ec::CurveGroup;
    for v in load_vectors("pedersen") {
        let x = codec::dec_scalar(&hexd(&v.sk).try_into().unwrap()).unwrap();
        let i = crate::vrf::hash_to_curve::hash_to_curve(&hexd(&v.alpha));
        let o = (i * x).into_affine();
        let ad = hexd(&v.ad);
        let (proof, b) = pedersen::prove(&x, &[(i, o)], &ad);
        assert_eq!(hex::encode(codec::enc_scalar(&b)), v.blinding, "blinding");
        assert_eq!(hex::encode(codec::enc_point(&proof.pk_com)), v.proof_pk_com, "pk_com");
        assert_eq!(hex::encode(codec::enc_point(&proof.r)), v.proof_r, "r");
        assert_eq!(hex::encode(codec::enc_point(&proof.ok)), v.proof_ok, "ok");
        assert_eq!(hex::encode(codec::enc_scalar(&proof.s)), v.proof_s, "s");
        assert_eq!(hex::encode(codec::enc_scalar(&proof.sb)), v.proof_sb, "sb");
        assert!(pedersen::verify(&[(i, o)], &ad, &proof), "verify");
        let y = codec::dec_point(&hexd(&v.pk).try_into().unwrap()).unwrap();
        assert!(pedersen::unblind(&proof.pk_com, &y, &b), "unblind");
        let mut bad = proof.clone();
        bad.s = bad.s + ark_ed_on_bls12_381_bandersnatch::Fr::from(1u64);
        assert!(!pedersen::verify(&[(i, o)], &ad, &bad), "verify rejects bad s");
    }
}

#[test]
fn verify_rejects_identity_and_bad_inputs() {
    use crate::vrf::{codec, tiny, thin, pedersen};
    use ark_ec::CurveGroup;
    use ark_ff::Zero;
    let id = ark_ed_on_bls12_381_bandersnatch::EdwardsAffine::zero();

    let v = &load_vectors("tiny")[0];
    let x = codec::dec_scalar(&hexd(&v.sk).try_into().unwrap()).unwrap();
    let i = crate::vrf::hash_to_curve::hash_to_curve(&hexd(&v.alpha));
    let o = (i * x).into_affine();
    let ad = hexd(&v.ad);
    let (c, s) = tiny::prove(&x, &[(i, o)], &ad);
    let y = codec::dec_point(&hexd(&v.pk).try_into().unwrap()).unwrap();
    let og = codec::dec_point(&hexd(&v.gamma).try_into().unwrap()).unwrap();
    assert!(tiny::verify(&y, &[(i, og)], &ad, &c, &s));
    assert!(!tiny::verify(&id, &[(i, og)], &ad, &c, &s), "tiny rejects identity Y");
    assert!(!tiny::verify(&y, &[(id, og)], &ad, &c, &s), "tiny rejects identity I");
    assert!(!tiny::verify(&y, &[(i, og)], &ad, &c[..1], &s), "tiny rejects short c");

    let tv = &load_vectors("thin")[0];
    let tx = codec::dec_scalar(&hexd(&tv.sk).try_into().unwrap()).unwrap();
    let ti = crate::vrf::hash_to_curve::hash_to_curve(&hexd(&tv.alpha));
    let to = (ti * tx).into_affine();
    let tad = hexd(&tv.ad);
    let (r, ts) = thin::prove(&tx, &[(ti, to)], &tad);
    let ty = codec::dec_point(&hexd(&tv.pk).try_into().unwrap()).unwrap();
    assert!(thin::verify(&ty, &[(ti, to)], &tad, &r, &ts));
    assert!(!thin::verify(&id, &[(ti, to)], &tad, &r, &ts), "thin rejects identity Y");
    assert!(!thin::verify(&ty, &[(ti, to)], &tad, &id, &ts), "thin rejects identity R");

    let pv = &load_vectors("pedersen")[0];
    let px = codec::dec_scalar(&hexd(&pv.sk).try_into().unwrap()).unwrap();
    let pi = crate::vrf::hash_to_curve::hash_to_curve(&hexd(&pv.alpha));
    let po = (pi * px).into_affine();
    let pad = hexd(&pv.ad);
    let (proof, _b) = pedersen::prove(&px, &[(pi, po)], &pad);
    assert!(pedersen::verify(&[(pi, po)], &pad, &proof));
    let mut bad = proof.clone();
    bad.pk_com = id;
    assert!(!pedersen::verify(&[(pi, po)], &pad, &bad), "pedersen rejects identity pk_com");
    assert!(!pedersen::verify(&[(id, po)], &pad, &proof), "pedersen rejects identity I");
}
