// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(clippy::pedantic, clippy::nursery, single_use_lifetimes, dead_code)]
use crate::bpf::mocks::MockMap;
use crate::bpf::mocks::MockTcProgram;
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
    DispatcherSkelBuilder,
    MockOpenDispatcherSkel,
    OpenDispatcherSkel,
    MockDispatcherSkel,
    DispatcherSkel,
    MockDispatcherProgs,
    MockDispatcherProgsMut,
    MockDispatcherMapsMut,
    MockDispatcherMaps
);

mock! {
    pub(crate) DispatcherProgs {
        pub(crate) fn tc_egress(&self) -> MockTcProgram;
    }
}

mock! {
    pub(crate) DispatcherProgsMut {
        pub(crate) fn tc_egress(&mut self) -> MockTcProgram;
    }
}

mock! {
    pub(crate) DispatcherMapsMut {
        pub(crate) fn num_streams(&mut self) -> &mut MockMap;
        pub(crate) fn streams(&mut self) -> &mut MockMap;
        pub(crate) fn stream_cgroups(&mut self) -> &mut MockMap;
    }
}

mock! {
    pub(crate) DispatcherMaps {
        pub(crate) fn num_streams(&mut self) -> &mut MockMap;
        pub(crate) fn streams(&mut self) -> &mut MockMap;
        pub(crate) fn stream_cgroups(&mut self) -> &mut MockMap;
    }
}
