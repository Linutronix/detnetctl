// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(clippy::pedantic, clippy::nursery, single_use_lifetimes)]
use anyhow::Result;
use libbpf_rs::MapFlags;
use libbpf_rs::TcAttachPoint;
use mockall::mock;

mock! {
    pub(crate) NetworkDispatcherSkelBuilder {
        pub(crate) fn open(mut self) -> libbpf_rs::Result<MockOpenNetworkDispatcherSkel>;
    }
}

pub(crate) mod network_dispatcher_rodata_types {
    #[derive(Debug, Copy, Clone)]
    #[repr(C)]
    pub(crate) struct rodata {
        pub(crate) debug_output: bool,
    }
}

mock! {
    pub(crate) OpenNetworkDispatcherSkel {
        pub(crate) fn load(mut self) -> libbpf_rs::Result<MockNetworkDispatcherSkel<'static>>;
        pub(crate) fn rodata(&mut self) -> &mut network_dispatcher_rodata_types::rodata;
    }
}

mock! {
    pub(crate) NetworkDispatcherSkel<'a> {
        pub(crate) fn progs(&self) -> MockNetworkDispatcherProgs;
        pub(crate) fn maps_mut(&mut self) -> MockNetworkDispatcherMapsMut;
        pub(crate) fn maps(&mut self) -> MockNetworkDispatcherMaps;
    }
}

mock! {
    pub(crate) NetworkDispatcherProgs {
        pub(crate) fn tc_egress(&self) -> MockProgram;
    }
}

mock! {
    pub(crate) NetworkDispatcherMapsMut {
        pub(crate) fn num_streams(&mut self) -> &mut MockMap;
        pub(crate) fn stream_handles(&mut self) -> &mut MockMap;
        pub(crate) fn streams(&mut self) -> &mut MockMap;
        pub(crate) fn stream_cgroups(&mut self) -> &mut MockMap;
    }
}

mock! {
    pub(crate) NetworkDispatcherMaps {
        pub(crate) fn num_streams(&mut self) -> &mut MockMap;
        pub(crate) fn stream_handles(&mut self) -> &mut MockMap;
        pub(crate) fn streams(&mut self) -> &mut MockMap;
        pub(crate) fn stream_cgroups(&mut self) -> &mut MockMap;
    }
}

mock! {
    pub(crate) Map {
        pub(crate) fn update(&self, key: &[u8], value: &[u8], flags: MapFlags) -> Result<()>;
        pub(crate) fn lookup(&self, key: &[u8], flags: MapFlags) -> Result<Option<Vec<u8>>>;
        pub(crate) fn info(&self) -> Result<MockMapInfo>;
    }
}

pub(crate) struct MockMapInfo {
    pub(crate) info: MockInnerMapInfo,
}

pub(crate) struct MockInnerMapInfo {
    pub(crate) max_entries: u32,
}

mock! {
    pub(crate) Program {
        pub(crate) fn as_fd(&self) -> i32;
    }
}

pub(crate) struct MockTcHookBuilder; // not with mock! since it does not properly support "-> &mut Self"

impl MockTcHookBuilder {
    pub(crate) fn new(_fd: i32) -> Self {
        Self {}
    }

    pub(crate) fn ifindex(&mut self, _ifindex: i32) -> &mut Self {
        self
    }

    pub(crate) fn replace(&mut self, _replace: bool) -> &mut Self {
        self
    }

    pub(crate) fn handle(&mut self, _handle: u32) -> &mut Self {
        self
    }

    pub(crate) fn priority(&mut self, _priority: u32) -> &mut Self {
        self
    }

    pub(crate) fn hook(&self, _attach_point: TcAttachPoint) -> MockTcHook {
        let mut tc_hook = MockTcHook::default();
        tc_hook.expect_create().times(1).returning(|| Ok(()));
        tc_hook.expect_attach().times(1).returning(|| Ok(()));
        tc_hook
    }
}

mock! {
    pub(crate) TcHook {
        pub(crate) fn create(&mut self) -> Result<()>;
        pub(crate) fn attach(&mut self) -> Result<()>;
    }
}
