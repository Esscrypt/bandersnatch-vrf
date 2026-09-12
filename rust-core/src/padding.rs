use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fq};
use ark_ff::MontFp;
use ark_serialize::CanonicalDeserialize;

pub(crate) const KEY_SIZE: usize = 32;
pub(crate) const MODULUS_BIT_SIZE: usize = 255;

pub(crate) const PADDING_POINT_BYTES: [u8; 32] = [
    0x92, 0xca, 0x79, 0xe6, 0x1d, 0xd9, 0x0c, 0x15,
    0x73, 0xa8, 0x69, 0x3f, 0x19, 0x9b, 0xf6, 0xe1,
    0xe8, 0x68, 0x35, 0xcc, 0x71, 0x5c, 0xdc, 0xf9,
    0x3f, 0x5e, 0xf2, 0x22, 0x56, 0x00, 0x23, 0xaa,
];

pub(crate) const SUITE_ID: &[u8] = b"Bandersnatch_SHA-512_ELL2";

pub(crate) const fn piop_domain_size_from_ring_size(ring_size: usize) -> usize {
    (ring_size + 4 + MODULUS_BIT_SIZE).next_power_of_two()
}

pub(crate) const fn max_ring_size_from_piop_domain(piop_domain_size: usize) -> usize {
    piop_domain_size.saturating_sub(4 + MODULUS_BIT_SIZE)
}

pub(crate) const fn pcs_domain_size_from_ring_size(ring_size: usize) -> usize {
    3 * piop_domain_size_from_ring_size(ring_size) + 1
}

pub(crate) fn bandersnatch_blinding_base() -> EdwardsAffine {
    EdwardsAffine::new_unchecked(
        MontFp!("6150229251051246713677296363717454238956877613358614224171740096471278798312"),
        MontFp!("28442734166467795856797249030329035618871580593056783094884474814923353898473"),
    )
}

pub(crate) fn bandersnatch_accumulator_base() -> EdwardsAffine {
    EdwardsAffine::new_unchecked(
        MontFp!("37805570861274048643170021838972902516980894313648523898085159469000338764576"),
        MontFp!("14738305321141000190236674389841754997202271418876976886494444739226156422510"),
    )
}

pub(crate) fn bandersnatch_padding() -> EdwardsAffine {
    EdwardsAffine::new_unchecked(
        MontFp!("26287722405578650394504321825321286533153045350760430979437739593351290020913"),
        MontFp!("19058981610000167534379068105702216971787064146691007947119244515951752366738"),
    )
}

pub(crate) fn padding_point() -> EdwardsAffine {
    EdwardsAffine::deserialize_compressed_unchecked(&PADDING_POINT_BYTES[..])
        .expect("Padding point is valid")
}

pub(crate) fn deserialize_ring_keys(ring_keys_bytes: &[u8]) -> Vec<EdwardsAffine> {
    let ring_size = ring_keys_bytes.len() / KEY_SIZE;
    let padding_point = padding_point();
    let mut ring_keys = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        let key_bytes = &ring_keys_bytes[i * KEY_SIZE..(i + 1) * KEY_SIZE];
        let is_null_key = key_bytes.iter().all(|&b| b == 0);
        let key = if is_null_key {
            padding_point
        } else {
            EdwardsAffine::deserialize_compressed_unchecked(key_bytes).unwrap_or(padding_point)
        };
        ring_keys.push(key);
    }
    ring_keys
}

pub(crate) fn keys_for_index(ring_keys: &[EdwardsAffine], piop_domain_size: usize) -> &[EdwardsAffine] {
    let max_ring_size = max_ring_size_from_piop_domain(piop_domain_size);
    if ring_keys.len() <= max_ring_size {
        ring_keys
    } else {
        &ring_keys[..max_ring_size]
    }
}

pub(crate) type PcsParams = w3f_pcs::pcs::kzg::urs::URS<ark_bls12_381::Bls12_381>;

pub(crate) fn ring_piop_params(
    piop_domain_size: usize,
) -> w3f_ring_proof::PiopParams<Fq, ark_ed_on_bls12_381_bandersnatch::BandersnatchConfig> {
    let domain = w3f_ring_proof::Domain::new(piop_domain_size, true);
    w3f_ring_proof::PiopParams::setup(
        domain,
        bandersnatch_blinding_base(),
        bandersnatch_accumulator_base(),
        bandersnatch_padding(),
    )
}
