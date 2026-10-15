#[cfg(panic = "abort")]
compile_error!(
    "pbnjam-bvrf-ffi requires unwind panics so caught panics become status 5; do not set panic = \"abort\""
);

mod abi;
mod exported_symbols;
mod handles;
mod status;

pub use abi::{
    pbnjam_bvrf_abi_version, pbnjam_bvrf_ietf_verify, pbnjam_bvrf_ring_batch_verify,
    pbnjam_bvrf_ring_prepare, pbnjam_bvrf_ring_release, pbnjam_bvrf_srs_open,
    pbnjam_bvrf_srs_release, pbnjam_bvrf_take_last_error, PbnjamBytesCb,
};
pub use exported_symbols::{ABI_VERSION, EXPORTED_SYMBOLS, FFI_FORMAT};

#[cfg(test)]
pub use abi::pbnjam_bvrf_force_panic_for_test;
