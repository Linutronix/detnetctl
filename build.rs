// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

//! Custom build steps for eBPF

#[cfg(feature = "bpf")]
use {
    libbpf_cargo::SkeletonBuilder,
    std::{env, path::PathBuf},
};

#[cfg(feature = "bpf")]
const BPFS: &[&str] = &["data_plane", "dispatcher"];

fn main() {
    build_bpf();
}

#[cfg(feature = "bpf")]
fn build_bpf() {
    for bpf in BPFS {
        let src = format!("./src/{bpf}/bpf/{bpf}.bpf.c");
        let mut out =
            PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
        out.push(format!("{bpf}.skel.rs"));
        SkeletonBuilder::new()
            .source(src.clone())
            .clang_args("-Werror")
            .build_and_generate(&out)
            .unwrap();
        println!("cargo:rerun-if-changed={src}");
    }
}

#[cfg(not(feature = "bpf"))]
const fn build_bpf() {}
