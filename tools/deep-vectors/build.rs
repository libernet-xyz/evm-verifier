use std::io::Result;
use std::path::PathBuf;

/// Generates a copy of the `starkom-pcs` protobuf messages with `serde` support, following the
/// canonical proto3 JSON mapping.
///
/// `starkom-pcs` exports the directory containing its `.proto` files through the `links` metadata
/// of its build script, and `prost` doesn't support JSON on its own, so we compile the same
/// definitions again here and let `pbjson` generate the `serde` implementations.
fn main() -> Result<()> {
    let proto_dir = PathBuf::from(std::env::var("DEP_STARKOM_PCS_V9_PROTO_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let descriptor_path = out_dir.join("descriptors.bin");

    prost_build::Config::new()
        .file_descriptor_set_path(&descriptor_path)
        .compile_well_known_types()
        .extern_path(".google.protobuf", "::pbjson_types")
        .compile_protos(&[proto_dir.join("pcs/pcs.proto")], &[proto_dir])?;

    pbjson_build::Builder::new()
        .register_descriptors(&std::fs::read(descriptor_path)?)?
        .build(&[".starkom"])?;

    Ok(())
}
