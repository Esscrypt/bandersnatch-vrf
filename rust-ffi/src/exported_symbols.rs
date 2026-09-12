pub struct ExportedSymbol {
    pub name: &'static str,
    pub params: &'static [&'static str],
    pub callback: bool,
    pub packed_schema: Option<&'static str>,
}

pub const ABI_VERSION: u32 = 1;
pub const FFI_FORMAT: u32 = 3;

pub const EXPORTED_SYMBOLS: &[ExportedSymbol] = &[
    ExportedSymbol {
        name: "pbnjam_bvrf_abi_version",
        params: &[],
        callback: false,
        packed_schema: None,
    },
    ExportedSymbol {
        name: "pbnjam_bvrf_ietf_verify",
        params: &["bytes"],
        callback: true,
        packed_schema: Some("bvrf_ietf_verify"),
    },
    ExportedSymbol {
        name: "pbnjam_bvrf_ring_batch_verify",
        params: &["u32", "u32", "bytes"],
        callback: true,
        packed_schema: Some("bvrf_ring_batch_verify"),
    },
    ExportedSymbol {
        name: "pbnjam_bvrf_ring_prepare",
        params: &["u32", "bytes"],
        callback: true,
        packed_schema: Some("bvrf_ring_prepare"),
    },
    ExportedSymbol {
        name: "pbnjam_bvrf_ring_release",
        params: &["u32"],
        callback: false,
        packed_schema: None,
    },
    ExportedSymbol {
        name: "pbnjam_bvrf_srs_open",
        params: &["bytes"],
        callback: true,
        packed_schema: Some("bvrf_srs_open"),
    },
    ExportedSymbol {
        name: "pbnjam_bvrf_srs_release",
        params: &["u32"],
        callback: false,
        packed_schema: None,
    },
    ExportedSymbol {
        name: "pbnjam_bvrf_take_last_error",
        params: &[],
        callback: true,
        packed_schema: Some("bvrf_last_error"),
    },
];
