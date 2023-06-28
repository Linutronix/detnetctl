// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Result};
use libbpf_rs::{set_print, MapFlags, PrintLevel, TC_EGRESS};
use std::collections::HashMap;

#[cfg(not(test))]
#[allow(clippy::pedantic, clippy::nursery, clippy::restriction)] // this is generated code
mod network_guard {
    include!(concat!(env!("OUT_DIR"), "/network_guard.skel.rs"));
}
#[cfg(not(test))]
use {
    libbpf_rs::TcHook, libbpf_rs::TcHookBuilder, network_guard::NetworkGuardSkel,
    network_guard::NetworkGuardSkelBuilder,
};

#[cfg(test)]
mod mocks;
#[cfg(test)]
use {
    mocks::MockNetworkGuardSkel as NetworkGuardSkel,
    mocks::MockNetworkGuardSkelBuilder as NetworkGuardSkelBuilder, mocks::MockTcHook as TcHook,
    mocks::MockTcHookBuilder as TcHookBuilder,
};

use crate::guard::Guard;

struct BPFInterface<'a> {
    _tc_egress: TcHook, // TODO check if persistence is really needed
    skel: NetworkGuardSkel<'a>,
}

type GenerateSkelCallback = Box<dyn FnMut() -> NetworkGuardSkelBuilder + Send>;
type NameToIndexCallback = Box<dyn FnMut(&str) -> Result<i32> + Send>;

/// Installs eBPFs to guard the network to prevent interference of real-time communication
pub struct BPFGuard<'a> {
    interfaces: HashMap<String, BPFInterface<'a>>,
    generate_skel: GenerateSkelCallback,
    nametoindex: NameToIndexCallback,
    debug_output: bool,
}

impl<'a> Guard for BPFGuard<'a> {
    fn protect_priority(&mut self, interface: &str, priority: u8, token: u64) -> Result<()> {
        let interf = if let Some(existing_interface) = self.interfaces.get_mut(interface) {
            existing_interface
        } else {
            self.attach_interface(interface)?;
            self.interfaces
                .get_mut(interface)
                .ok_or_else(|| anyhow!("Interface missing even after attach"))?
        };

        interf.protect_priority(priority, token)
    }
}

impl<'a> BPFGuard<'a> {
    /// Create a new `BPFGuard`
    pub fn new(debug_output: bool) -> Self {
        set_print(Some((PrintLevel::Debug, print_to_log)));
        BPFGuard {
            interfaces: HashMap::default(),
            generate_skel: Box::new(NetworkGuardSkelBuilder::default),
            nametoindex: Box::new(|interface| {
                Ok(i32::try_from(nix::net::if_::if_nametoindex(interface)?)?)
            }),
            debug_output,
        }
    }

    fn attach_interface(&mut self, interface: &str) -> Result<()> {
        let skel_builder = (self.generate_skel)();
        let mut open_skel = skel_builder.open()?;
        open_skel.rodata().debug_output = self.debug_output;

        let skel = open_skel.load()?;

        let fd = skel.progs().tc_egress().fd();
        let ifidx = (self.nametoindex)(interface)?;

        let mut tc_builder = TcHookBuilder::new();
        tc_builder
            .fd(fd)
            .ifindex(ifidx)
            .replace(true)
            .handle(1)
            .priority(1);

        let mut tc_egress = tc_builder.hook(TC_EGRESS);

        tc_egress.create()?;
        tc_egress.attach()?;

        self.interfaces.insert(
            String::from(interface),
            BPFInterface {
                _tc_egress: tc_egress,
                skel,
            },
        );
        Ok(())
    }
}

impl<'a> Default for BPFGuard<'a> {
    fn default() -> Self {
        Self::new(false)
    }
}

impl<'a> BPFInterface<'a> {
    pub fn protect_priority(&mut self, priority: u8, token: u64) -> Result<()> {
        let key = priority.to_ne_bytes();
        let val = token.to_ne_bytes();
        self.skel
            .maps_mut()
            .allowed_tokens()
            .update(&key, &val, MapFlags::ANY)?;
        Ok(())
    }
}

#[allow(clippy::needless_pass_by_value)] // interface defined by libbpf-rs
fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => log::debug!("{}", msg),
        PrintLevel::Info => log::info!("{}", msg),
        PrintLevel::Warn => log::warn!("{}", msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use mocks::MockMap as Map;
    use mocks::MockNetworkGuardMapsMut as NetworkGuardMapsMut;
    use mocks::MockNetworkGuardProgs as NetworkGuardProgs;
    use mocks::MockOpenNetworkGuardSkel as OpenNetworkGuardSkel;
    use mocks::MockProgram as Program;

    const INTERFACE: &str = "eth12";
    const PRIORITY: u8 = 6;
    const TOKEN: u64 = 0x9876_1234_1234_1298;

    fn generate_skel_builder() -> NetworkGuardSkelBuilder {
        let mut builder = NetworkGuardSkelBuilder::default();
        builder
            .expect_open()
            .times(1)
            .returning(|| Ok(generate_open_skel()));
        builder
    }

    fn generate_open_skel() -> OpenNetworkGuardSkel {
        let mut open_skel = OpenNetworkGuardSkel::default();
        open_skel
            .expect_load()
            .times(1)
            .returning(|| Ok(generate_skel()));
        open_skel.expect_rodata().times(1).returning(|| {
            mocks::network_guard_rodata_types::rodata {
                debug_output: false,
            }
        });
        open_skel
    }

    fn generate_skel<'a>() -> NetworkGuardSkel<'a> {
        let mut skel = NetworkGuardSkel::default();
        skel.expect_progs().times(1).returning(generate_progs);
        skel.expect_maps_mut().returning(generate_maps_mut);
        skel
    }

    fn generate_progs() -> NetworkGuardProgs {
        let mut progs = NetworkGuardProgs::default();
        progs
            .expect_tc_egress()
            .times(1)
            .returning(generate_program);
        progs
    }

    fn generate_program() -> Program {
        let mut prog = Program::default();
        prog.expect_fd().times(1).return_const(1);
        prog
    }

    fn generate_maps_mut() -> NetworkGuardMapsMut {
        let mut maps_mut = NetworkGuardMapsMut::default();
        maps_mut.expect_allowed_tokens().returning(|| {
            let mut map = Map::default();
            map.expect_update()
                .times(1)
                .returning(|priority, token, _| {
                    assert_eq!(*priority, PRIORITY.to_ne_bytes());
                    assert_eq!(*token, TOKEN.to_ne_bytes());
                    Ok(())
                });
            map
        });
        maps_mut
    }

    #[test]
    fn test_happy() -> Result<()> {
        let mut guard = BPFGuard {
            interfaces: HashMap::default(),
            generate_skel: Box::new(generate_skel_builder),
            nametoindex: Box::new(|interface| {
                assert_eq!(interface, INTERFACE);
                Ok(3)
            }),
            debug_output: false,
        };

        guard.protect_priority(INTERFACE, PRIORITY, TOKEN)?;
        Ok(())
    }

    #[test]
    #[should_panic(expected = "interface not found")]
    fn test_interface_not_found() {
        let mut guard = BPFGuard {
            interfaces: HashMap::default(),
            generate_skel: Box::new(generate_skel_builder),
            nametoindex: Box::new(|interface| {
                assert_eq!(interface, INTERFACE);
                Err(anyhow!("interface not found"))
            }),
            debug_output: false,
        };

        guard.protect_priority(INTERFACE, PRIORITY, TOKEN).unwrap();
    }
}
