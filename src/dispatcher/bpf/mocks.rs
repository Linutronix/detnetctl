// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(clippy::pedantic, clippy::nursery, single_use_lifetimes)]
use anyhow::Result;
use libbpf_rs::MapFlags;
use libbpf_rs::TcAttachPoint;
use mockall::mock;

mock! {
    pub NetworkDispatcherSkelBuilder {
        pub fn open(mut self) -> libbpf_rs::Result<MockOpenNetworkDispatcherSkel>;
    }
}

pub mod network_dispatcher_rodata_types {
    #[derive(Debug, Copy, Clone)]
    #[repr(C)]
    pub struct rodata {
        pub debug_output: bool,
    }
}

mock! {
    pub OpenNetworkDispatcherSkel {
        pub fn load(mut self) -> libbpf_rs::Result<MockNetworkDispatcherSkel<'static>>;
        pub fn rodata(&mut self) -> &mut network_dispatcher_rodata_types::rodata;
    }
}

mock! {
    pub NetworkDispatcherSkel<'a> {
        pub fn progs(&self) -> MockNetworkDispatcherProgs;
        pub fn maps_mut(&mut self) -> MockNetworkDispatcherMapsMut;
        pub fn maps(&mut self) -> MockNetworkDispatcherMaps;
    }
}

mock! {
    pub NetworkDispatcherProgs {
        pub fn tc_egress(&self) -> MockProgram;
    }
}

mock! {
    pub NetworkDispatcherMapsMut {
        pub fn num_streams(&mut self) -> &mut MockMap;
        pub fn stream_handles(&mut self) -> &mut MockMap;
        pub fn streams(&mut self) -> &mut MockMap;
        pub fn stream_cgroups(&mut self) -> &mut MockMap;
    }
}

mock! {
    pub NetworkDispatcherMaps {
        pub fn num_streams(&mut self) -> &mut MockMap;
        pub fn stream_handles(&mut self) -> &mut MockMap;
        pub fn streams(&mut self) -> &mut MockMap;
        pub fn stream_cgroups(&mut self) -> &mut MockMap;
    }
}

mock! {
    pub Map {
        pub fn update(&self, key: &[u8], value: &[u8], flags: MapFlags) -> Result<()>;
        pub fn lookup(&self, key: &[u8], flags: MapFlags) -> Result<Option<Vec<u8>>>;
        pub fn info(&self) -> Result<MockMapInfo>;
    }
}

pub struct MockMapInfo {
    pub info: MockInnerMapInfo,
}

pub struct MockInnerMapInfo {
    pub max_entries: u32,
}

mock! {
    pub Program {
        pub fn as_fd(&self) -> i32;
    }
}

pub struct MockTcHookBuilder; // not with mock! since it does not properly support "-> &mut Self"

impl MockTcHookBuilder {
    pub fn new(_fd: i32) -> Self {
        Self {}
    }

    pub fn ifindex(&mut self, _ifindex: i32) -> &mut Self {
        self
    }

    pub fn replace(&mut self, _replace: bool) -> &mut Self {
        self
    }

    pub fn handle(&mut self, _handle: u32) -> &mut Self {
        self
    }

    pub fn priority(&mut self, _priority: u32) -> &mut Self {
        self
    }

    pub fn hook(&self, _attach_point: TcAttachPoint) -> MockTcHook {
        let mut tc_hook = MockTcHook::default();
        tc_hook.expect_create().times(1).returning(|| Ok(()));
        tc_hook.expect_attach().times(1).returning(|| Ok(()));
        tc_hook
    }
}

mock! {
    pub TcHook {
        pub fn create(&mut self) -> Result<()>;
        pub fn attach(&mut self) -> Result<()>;
    }
}
