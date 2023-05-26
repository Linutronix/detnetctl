#![allow(clippy::pedantic, clippy::nursery)]
use anyhow::Result;
use libbpf_rs::MapFlags;
use libbpf_rs::TcAttachPoint;
use mockall::mock;

mock! {
    pub NetworkGuardSkelBuilder {
        pub fn open(mut self) -> libbpf_rs::Result<MockOpenNetworkGuardSkel>;
    }
}

pub mod network_guard_rodata_types {
    #[derive(Debug, Copy, Clone)]
    #[repr(C)]
    pub struct rodata {
        pub debug_output: bool,
    }
}

mock! {
    pub OpenNetworkGuardSkel {
        pub fn load(mut self) -> libbpf_rs::Result<MockNetworkGuardSkel<'static>>;
        pub fn rodata(&mut self) -> &mut network_guard_rodata_types::rodata;
    }
}

mock! {
    pub NetworkGuardSkel<'a> {
        pub fn progs(&self) -> MockNetworkGuardProgs;
        pub fn maps_mut(&mut self) -> MockNetworkGuardMapsMut;
    }
}

mock! {
    pub NetworkGuardProgs {
        pub fn tc_egress(&self) -> MockProgram;
    }
}

mock! {
    pub NetworkGuardMapsMut {
        pub fn allowed_tokens(&mut self) -> &mut MockMap;
    }
}

mock! {
    pub Map {
        pub fn update(&self, key: &[u8; 1], value: &[u8; 8], flags: MapFlags) -> Result<()>;
    }
}

mock! {
    pub Program {
        pub fn fd(&self) -> i32;
    }
}

pub struct MockTcHookBuilder; // not with mock! since it does not properly support "-> &mut Self"

impl MockTcHookBuilder {
    pub fn new() -> Self {
        Self {}
    }

    pub fn fd(&mut self, _fd: i32) -> &mut Self {
        self
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
