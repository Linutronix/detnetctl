// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(clippy::pedantic, clippy::nursery, single_use_lifetimes)]
use libbpf_rs::MapFlags;
use libbpf_rs::Result;
use libbpf_rs::TcAttachPoint;
use libbpf_rs::XdpFlags;
use mockall::mock;
use std::os::fd::BorrowedFd;
use std::path::Path;

#[macro_export]
macro_rules! bpf_mock {
    ($skelBuilder:ident,
     $mockOpenSkel:ident,
     $openSkel:ident,
     $mockSkel:ident,
     $skel:ident,
     $mockProgs:ident,
     $mockProgsMut:ident,
     $mockMapsMut:ident,
     $mockMaps:ident,
     $rodata_types:ident
     ) => {
        mock! {
            pub(crate) $skelBuilder {
                pub(crate) fn open(mut self) -> libbpf_rs::Result<$mockOpenSkel<'static>>;
            }
        }

        mock! {
            pub(crate) $openSkel<'a> {
                pub(crate) fn load(mut self) -> libbpf_rs::Result<$mockSkel<'static>>;
                pub(crate) fn rodata_mut(&mut self) -> &mut $rodata_types::rodata;
            }
        }

        mock! {
            pub(crate) $skel<'a> {
                pub(crate) fn progs(&self) -> $mockProgs;
                pub(crate) fn progs_mut(&mut self) -> $mockProgsMut;
                pub(crate) fn maps_mut(&mut self) -> $mockMapsMut;
                pub(crate) fn maps(&mut self) -> $mockMaps;
                pub(crate) fn rodata(&self) -> $rodata_types::rodata;
            }
        }
    };
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
    pub(crate) value_size: u32,
}

mock! {
    pub(crate) XdpProgram {
        pub(crate) fn as_fd(&self) -> BorrowedFd<'_>;
        pub(crate) fn pin(&mut self, path: &Path) -> Result<()>;
    }
}

mock! {
    pub(crate) TcProgram {
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

pub(crate) struct MockXdp;
impl MockXdp {
    pub(crate) fn new(_fd: BorrowedFd<'_>) -> Self {
        Self {}
    }

    pub(crate) fn attach(&self, _ifindex: i32, _flags: XdpFlags) -> Result<()> {
        Ok(())
    }
}
