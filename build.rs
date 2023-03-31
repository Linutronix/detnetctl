use std::io::Result;
#[cfg(feature = "bpf")]
use {
    libbpf_cargo::SkeletonBuilder,
    std::{env, path::PathBuf},
};

#[cfg(feature = "bpf")]
const BPF_SRC: &str = "./src/guard/bpf/network_guard.bpf.c";

fn main() -> Result<()> {
    build_bpf();
    Ok(())
}

#[cfg(all(feature = "bpf", feature = "libbpf_with_sotoken"))]
const BPF_FLAGS: &str = "-DLIBBPF_WITH_SOTOKEN";
#[cfg(all(feature = "bpf", not(feature = "libbpf_with_sotoken")))]
const BPF_FLAGS: &str = "";

#[cfg(feature = "bpf")]
fn build_bpf() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("network_guard.skel.rs");
    SkeletonBuilder::new()
        .source(BPF_SRC)
        .clang_args(BPF_FLAGS)
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={BPF_SRC}");
}

#[cfg(not(feature = "bpf"))]
fn build_bpf() {}
