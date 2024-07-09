// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(clippy::pedantic, clippy::nursery, single_use_lifetimes, dead_code)]
use crate::bpf::mocks::MockMap;
use crate::bpf::mocks::MockXdpProgram;
use crate::bpf_mock;
use libbpf_rs::libbpf_sys;
use libbpf_rs::{MapFlags, MapType, Result};
use mockall::mock;
use std::ffi::OsStr;
use std::os::fd::BorrowedFd;

pub(crate) mod bpf_rodata_types {
    #[derive(Debug, Copy, Clone)]
    #[repr(C)]
    pub(crate) struct rodata {
        pub(crate) debug_output: bool,
    }
}

bpf_mock!(
    DataPlaneSkelBuilder,
    MockOpenDataPlaneSkel,
    OpenDataPlaneSkel,
    MockDataPlaneSkel,
    DataPlaneSkel,
    MockDataPlaneProgs,
    MockDataPlaneProgsMut,
    MockDataPlaneMapsMut,
    MockDataPlaneMaps,
    bpf_rodata_types
);

mock! {
    pub(crate) DataPlaneProgs {
        pub(crate) fn xdp_bridge(&self) -> MockXdpProgram;
        pub(crate) fn pass(&self) -> MockXdpProgram;
    }
}

mock! {
    pub(crate) DataPlaneProgsMut {
        pub(crate) fn xdp_bridge(&mut self) -> MockXdpProgram;
        pub(crate) fn pass(&mut self) -> MockXdpProgram;
    }
}

mock! {
    pub(crate) DataPlaneMapsMut {
        pub(crate) fn num_streams(&mut self) -> &mut MockMap;
        pub(crate) fn streams(&mut self) -> &mut MockMap;
        pub(crate) fn redirect_map(&mut self) -> &mut MockMap;
        pub(crate) fn seqgen_map(&mut self) -> &mut MockMap;
        pub(crate) fn seqrcvy_map(&mut self) -> &mut MockMap;
    }
}

mock! {
    pub(crate) DataPlaneMaps {
        pub(crate) fn num_streams(&mut self) -> &mut MockMap;
        pub(crate) fn streams(&mut self) -> &mut MockMap;
        pub(crate) fn seqgen_map(&mut self) -> &mut MockMap;
        pub(crate) fn seqrcvy_map(&mut self) -> &mut MockMap;
    }
}

mock! {
    pub(crate) MapHandle {
        pub(crate) fn create<T: AsRef<OsStr> + 'static>(
            map_type: MapType,
            name: Option<T>,
            key_size: u32,
            value_size: u32,
            max_entries: u32,
            opts: &libbpf_sys::bpf_map_create_opts,
        ) -> Result<Self>;

        pub(crate) fn update(&self, key: &[u8], value: &[u8], flags: MapFlags) -> Result<()>;

        pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
            // SAFETY:
            // Only for testing
            BorrowedFd::borrow_raw(0)
        }
    }
}

pub(crate) mod postprocessing_rodata_types {
    #[derive(Debug, Default, Copy, Clone)]
    #[repr(C)]
    #[allow(non_snake_case)]
    pub(crate) struct vlan_ethhdr {
        pub(crate) __anon_1: __anon_1,
        pub(crate) h_vlan_proto: u16,
        pub(crate) h_vlan_TCI: u16,
        pub(crate) h_vlan_encapsulated_proto: u16,
    }
    #[derive(Copy, Clone)]
    #[repr(C)]
    pub(crate) union __anon_1 {
        pub(crate) __anon_2: __anon_2,
        pub(crate) addrs: __anon_2,
    }
    impl std::fmt::Debug for __anon_1 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "(???)")
        }
    }
    impl Default for __anon_1 {
        fn default() -> Self {
            __anon_1 {
                __anon_2: __anon_2::default(),
            }
        }
    }
    #[derive(Debug, Default, Copy, Clone)]
    #[repr(C)]
    pub(crate) struct __anon_2 {
        pub(crate) h_dest: [u8; 6],
        pub(crate) h_source: [u8; 6],
    }

    #[derive(Debug, Copy, Clone)]
    #[repr(C)]
    pub(crate) struct rodata {
        pub(crate) debug_output: bool,
        pub(crate) overwrite_source_addr: bool,
        pub(crate) overwrite_dest_addr: bool,
        pub(crate) overwrite_vlan_proto_and_tci: bool,
        pub(crate) overwrite_ether_type: bool,
        pub(crate) target_outer_hdr: vlan_ethhdr,
    }
}

bpf_mock!(
    PostprocessingSkelBuilder,
    MockOpenPostprocessingSkel,
    OpenPostprocessingSkel,
    MockPostprocessingSkel,
    PostprocessingSkel,
    MockPostprocessingProgs,
    MockPostprocessingProgsMut,
    MockPostprocessingMapsMut,
    MockPostprocessingMaps,
    postprocessing_rodata_types
);

mock! {
    pub(crate) PostprocessingProgs {
        pub(crate) fn xdp_bridge_postprocessing(&self) -> MockXdpProgram;
    }
}

mock! {
    pub(crate) PostprocessingProgsMut {
        pub(crate) fn xdp_bridge_postprocessing(&mut self) -> MockXdpProgram;
    }
}

mock! {
    #[allow(clippy::empty_structs_with_brackets)]
    pub(crate) PostprocessingMapsMut {
    }
}

mock! {
    #[allow(clippy::empty_structs_with_brackets)]
    pub(crate) PostprocessingMaps {
    }
}
