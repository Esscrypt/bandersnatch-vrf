//! Batched ring VRF verification.
//!
//! `vendored/` is a faithful copy of the w3f-ring-proof 0.0.2 verify path (same source, hence
//! identical proof semantics and byte formats), re-rooted under this module and extended with an
//! `openings_for` method that returns a proof's KZG openings instead of performing the pairing.
//! This lets us aggregate the openings of many proofs into a single multi-pairing check.

pub mod vendored;
