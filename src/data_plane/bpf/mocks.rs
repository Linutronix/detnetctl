// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(clippy::pedantic, clippy::nursery, single_use_lifetimes, dead_code)]
use crate::bpf::mocks::MockMap;
use crate::bpf::mocks::MockXdpProgram;
use crate::bpf_mock;
use mockall::mock;

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
    MockDataPlaneMaps
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
    }
}

mock! {
    pub(crate) DataPlaneMaps {
        pub(crate) fn num_streams(&mut self) -> &mut MockMap;
        pub(crate) fn streams(&mut self) -> &mut MockMap;
    }
}
