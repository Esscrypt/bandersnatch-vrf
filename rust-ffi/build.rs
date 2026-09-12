use std::env;
use std::fs;
use std::path::PathBuf;

#[path = "src/exported_symbols.rs"]
mod exported_symbols;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/abi.rs");
    println!("cargo:rerun-if-changed=src/exported_symbols.rs");

    let mut json = String::new();
    json.push_str("{\n");
    json.push_str(&format!(
        "  \"abi_version\": {},\n",
        exported_symbols::ABI_VERSION
    ));
    json.push_str(&format!(
        "  \"ffi_format\": {},\n",
        exported_symbols::FFI_FORMAT
    ));
    json.push_str("  \"symbols\": [\n");
    for (index, symbol) in exported_symbols::EXPORTED_SYMBOLS.iter().enumerate() {
        json.push_str("    {\n");
        json.push_str(&format!("      \"callback\": {},\n", symbol.callback));
        json.push_str(&format!("      \"name\": \"{}\",\n", symbol.name));
        match symbol.packed_schema {
            Some(schema) => json.push_str(&format!("      \"packed_schema\": \"{schema}\",\n")),
            None => json.push_str("      \"packed_schema\": null,\n"),
        }
        json.push_str("      \"params\": [");
        for (param_index, param) in symbol.params.iter().enumerate() {
            if param_index > 0 {
                json.push_str(", ");
            }
            json.push_str(&format!("\"{param}\""));
        }
        json.push_str("]\n");
        json.push_str("    }");
        if index + 1 != exported_symbols::EXPORTED_SYMBOLS.len() {
            json.push(',');
        }
        json.push('\n');
    }
    json.push_str("  ]\n");
    json.push_str("}\n");

    let dest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ffi.json");
    fs::write(&dest, json).expect("write ffi.json");
}
