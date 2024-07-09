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
    MockDataPlaneMapsMut,
    MockDataPlaneMaps
);

mock! {
    pub(crate) DataPlaneProgs {
        pub(crate) fn xdp_bridge(&self) -> MockXdpProgram;
    }
}

mock! {
    pub(crate) DataPlaneMapsMut {
        pub(crate) fn num_streams(&mut self) -> &mut MockMap;
        pub(crate) fn streams(&mut self) -> &mut MockMap;
        pub(crate) fn redirect_map(&mut self) -> &mut MockMap;
    }
}

mock! {
    pub(crate) DataPlaneMaps {
        pub(crate) fn num_streams(&mut self) -> &mut MockMap;
        pub(crate) fn streams(&mut self) -> &mut MockMap;
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
