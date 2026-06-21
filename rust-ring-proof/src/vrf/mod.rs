//! Self-contained Bandersnatch Tiny/Thin/Pedersen VRF (W3F spec Draft 34).
//! No `ark-vrf` dependency: codec + SHA-512 transcript + arkworks 0.5 curve ops.

pub mod codec;
pub mod transcript;
pub mod procedures;
pub mod hash_to_curve;
pub mod tiny;
pub mod thin;
pub mod pedersen;

#[cfg(test)]
mod tests;
