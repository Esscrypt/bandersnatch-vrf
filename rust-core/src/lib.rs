//! Runtime-agnostic ring proof and IETF VRF core.
//!
//! Holds the ark-vrf / w3f-ring-proof work previously inlined in the `#[napi]` bodies of
//! `rust-ring-proof`. No `napi` types. Consumed by the Node-API cdylib and later by the C ABI.

mod batch;
mod padding;
pub mod ietf;
pub mod packed;
pub mod ring;

pub use ietf::{prove_ietf_vrf, verify_ietf_vrf};
pub use ring::{
    batch_verify_ring_vrf, compute_ring_commitment, compute_ring_verifier_key, prove_ring_proof,
    verify_ring_vrf, verify_ring_vrf_with_key, RingBatchItemBytes,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreError(String);

impl CoreError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CoreError {}
