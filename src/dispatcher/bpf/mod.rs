// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Context, Result};
use libbpf_rs::{set_print, MapFlags, PrintLevel, TC_EGRESS};
use std::collections::HashMap;

#[cfg(not(test))]
#[allow(clippy::pedantic, clippy::nursery, clippy::restriction)] // this is generated code
mod network_dispatcher {
    include!(concat!(env!("OUT_DIR"), "/network_dispatcher.skel.rs"));
}
#[cfg(not(test))]
use {
    libbpf_rs::skel::{OpenSkel, SkelBuilder},
    libbpf_rs::TcHook,
    libbpf_rs::TcHookBuilder,
    network_dispatcher::NetworkDispatcherSkel,
    network_dispatcher::NetworkDispatcherSkelBuilder,
    std::os::fd::AsFd,
};

#[cfg(test)]
mod mocks;
#[cfg(test)]
use {
    mocks::MockNetworkDispatcherSkel as NetworkDispatcherSkel,
    mocks::MockNetworkDispatcherSkelBuilder as NetworkDispatcherSkelBuilder,
    mocks::MockTcHook as TcHook, mocks::MockTcHookBuilder as TcHookBuilder,
};

use crate::dispatcher::{Dispatcher, StreamIdentification};

#[derive(Debug)]
struct Stream {
    restrictions: u8,
    socket_token: u64, // only read if indicated by restrictions
    shifted_pcp: u16,
    egress_priority: u32,
}

impl Stream {
    fn new(priority: u32, pcp: u8, token: Option<u64>) -> Self {
        let shifted_pcp: u16 = u16::from(pcp) << 13;
        token.map_or(
            Self {
                restrictions: 0,
                socket_token: 0,
                shifted_pcp,
                egress_priority: priority,
            },
            |socket_token| Self {
                restrictions: 1,
                socket_token,
                shifted_pcp,
                egress_priority: priority,
            },
        )
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 15] {
        let mut result: [u8; 15] = [0; 15];
        result[0] = self.restrictions;
        result[1..9].copy_from_slice(&self.socket_token.to_ne_bytes()[..]);
        result[9..11].copy_from_slice(&self.shifted_pcp.to_ne_bytes()[..]);
        result[11..15].copy_from_slice(&self.egress_priority.to_ne_bytes()[..]);
        result
    }

    #[cfg(test)]
    pub fn from_bytes(bytes: [u8; 15]) -> Result<Self> {
        Ok(Self {
            restrictions: bytes[0],
            socket_token: u64::from_ne_bytes(
                bytes[1..9]
                    .try_into()
                    .map_err(|_e| anyhow!("Invalid byte number"))?,
            ),
            shifted_pcp: u16::from_ne_bytes(
                bytes[9..11]
                    .try_into()
                    .map_err(|_e| anyhow!("Invalid byte number"))?,
            ),
            egress_priority: u32::from_ne_bytes(
                bytes[11..15]
                    .try_into()
                    .map_err(|_e| anyhow!("Invalid byte number"))?,
            ),
        })
    }
}

struct BPFInterface<'a> {
    _tc_egress: TcHook, // TODO check if persistence is really needed
    skel: NetworkDispatcherSkel<'a>,
}

type GenerateSkelCallback = Box<dyn FnMut() -> NetworkDispatcherSkelBuilder + Send>;
type NameToIndexCallback = Box<dyn FnMut(&str) -> Result<i32> + Send>;

/// Installs eBPFs to dispatcher the network to prevent interference of real-time communication
pub struct BPFDispatcher<'a> {
    interfaces: HashMap<String, BPFInterface<'a>>,
    generate_skel: GenerateSkelCallback,
    nametoindex: NameToIndexCallback,
    debug_output: bool,
}

impl<'a> Dispatcher for BPFDispatcher<'a> {
    fn configure_stream(
        &mut self,
        interface: &str,
        stream_identification: &StreamIdentification,
        priority: u32,
        pcp: u8,
        token: Option<u64>,
    ) -> Result<()> {
        self.with_interface(interface, |iface| {
            iface
                .configure_stream(stream_identification, priority, pcp, token)
                .context("Failed to configure stream")
        })
    }

    fn configure_best_effort(
        &mut self,
        interface: &str,
        priority: u32,
        token: Option<u64>,
    ) -> Result<()> {
        self.with_interface(interface, |iface| {
            iface
                .configure_best_effort(priority, token)
                .context("Failed to configure best effort")
        })
    }
}

impl<'a> BPFDispatcher<'a> {
    /// Create a new `BPFDispatcher`
    pub fn new(debug_output: bool) -> Self {
        set_print(Some((PrintLevel::Debug, print_to_log)));
        BPFDispatcher {
            interfaces: HashMap::default(),
            generate_skel: Box::new(NetworkDispatcherSkelBuilder::default),
            nametoindex: Box::new(|interface| {
                Ok(i32::try_from(nix::net::if_::if_nametoindex(interface)?)?)
            }),
            debug_output,
        }
    }

    fn with_interface(
        &mut self,
        interface: &str,
        f: impl FnOnce(&mut BPFInterface) -> Result<()>,
    ) -> Result<()> {
        if let Some(existing_interface) = self.interfaces.get_mut(interface) {
            f(existing_interface)
        } else {
            self.attach_interface(interface)
                .context("Failed to attach eBPF to interface")?;
            f(self
                .interfaces
                .get_mut(interface)
                .ok_or_else(|| anyhow!("Interface missing even after attach"))?)
        }
    }

    fn attach_interface(&mut self, interface: &str) -> Result<()> {
        let skel_builder = (self.generate_skel)();
        let mut open_skel = skel_builder.open()?;
        open_skel.rodata().debug_output = self.debug_output;

        let mut skel = open_skel.load()?;

        let ifidx = (self.nametoindex)(interface)?;

        let progs = skel.progs();
        let mut tc_builder = TcHookBuilder::new(progs.tc_egress().as_fd());
        tc_builder
            .ifindex(ifidx)
            .replace(true)
            .handle(1)
            .priority(1);

        let mut tc_egress = tc_builder.hook(TC_EGRESS);

        tc_egress.create()?;
        tc_egress.attach()?;

        // configure default best-effort
        skel.maps_mut().streams().update(
            &0_u32.to_ne_bytes(),
            &Stream::new(0, 0, None).to_bytes(),
            MapFlags::ANY,
        )?;

        skel.maps_mut().num_streams().update(
            &0_u32.to_ne_bytes(),
            &1_u16.to_ne_bytes(),
            MapFlags::ANY,
        )?;

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

impl<'a> Default for BPFDispatcher<'a> {
    fn default() -> Self {
        Self::new(false)
    }
}

impl<'a> BPFInterface<'a> {
    pub fn configure_stream(
        &mut self,
        stream_identification: &StreamIdentification,
        priority: u32,
        pcp: u8,
        token: Option<u64>,
    ) -> Result<()> {
        let stream_id_bytes = stream_identification.to_bytes();

        // Check if stream already exists, otherwise calculate stream_handle from number of streams
        let mut adding_new_stream = false;
        let stream_handle = if let Some(s) = self
            .skel
            .maps()
            .stream_handles()
            .lookup(&stream_id_bytes, MapFlags::ANY)?
        {
            u16::from_ne_bytes(s.try_into().map_err(|_e| anyhow!("Invalid byte number"))?)
        } else {
            adding_new_stream = true;
            let num_streams = u16::from_ne_bytes(
                self.skel
                    .maps()
                    .num_streams()
                    .lookup(&0_u32.to_ne_bytes(), MapFlags::ANY)?
                    .ok_or_else(|| anyhow!("Cannot lookup number of streams"))?
                    .try_into()
                    .map_err(|_e| anyhow!("Invalid byte number"))?,
            );

            let max_streams: u16 = self
                .skel
                .maps()
                .streams()
                .info()?
                .info
                .max_entries
                .try_into()?;

            if num_streams == max_streams {
                return Err(anyhow!("Maximum number of streams reached"));
            }

            num_streams
        };

        self.skel.maps_mut().streams().update(
            &u32::from(stream_handle).to_ne_bytes(),
            &Stream::new(priority, pcp, token).to_bytes(),
            MapFlags::ANY,
        )?;

        if adding_new_stream {
            let new_num_streams = stream_handle + 1;

            self.skel.maps_mut().num_streams().update(
                &0_u32.to_ne_bytes(),
                &new_num_streams.to_ne_bytes(),
                MapFlags::ANY,
            )?;

            self.skel.maps_mut().stream_handles().update(
                &stream_id_bytes,
                &stream_handle.to_ne_bytes(),
                MapFlags::ANY,
            )?;
        }

        Ok(())
    }

    pub fn configure_best_effort(&mut self, priority: u32, token: Option<u64>) -> Result<()> {
        self.skel.maps_mut().streams().update(
            &0_u32.to_ne_bytes(),
            &Stream::new(priority, 0 /* best-effort PCP */, token).to_bytes(),
            MapFlags::ANY,
        )?;

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
    use eui48::MacAddress;
    use mocks::MockMap as Map;
    use mocks::MockNetworkDispatcherMaps as NetworkDispatcherMaps;
    use mocks::MockNetworkDispatcherMapsMut as NetworkDispatcherMapsMut;
    use mocks::MockNetworkDispatcherProgs as NetworkDispatcherProgs;
    use mocks::MockOpenNetworkDispatcherSkel as OpenNetworkDispatcherSkel;
    use mocks::MockProgram as Program;
    use mocks::{MockInnerMapInfo, MockMapInfo};

    const INTERFACE: &str = "eth12";
    const PCP: u8 = 3;
    const PRIORITY: u32 = 6;
    const TOKEN: u64 = 0x9876_1234_1234_1298;
    const STREAM_ID: StreamIdentification = StreamIdentification {
        destination_address: MacAddress::new([0xab, 0xcb, 0xcb, 0xcb, 0xcb, 0xcb]),
        vlan_identifier: 3,
    };

    fn generate_skel_builder() -> NetworkDispatcherSkelBuilder {
        let mut builder = NetworkDispatcherSkelBuilder::default();
        builder
            .expect_open()
            .times(1)
            .returning(|| Ok(generate_open_skel()));
        builder
    }

    fn generate_open_skel() -> OpenNetworkDispatcherSkel {
        let mut open_skel = OpenNetworkDispatcherSkel::default();
        open_skel
            .expect_load()
            .times(1)
            .returning(|| Ok(generate_skel()));
        open_skel.expect_rodata().times(1).returning(|| {
            mocks::network_dispatcher_rodata_types::rodata {
                debug_output: false,
            }
        });
        open_skel
    }

    fn generate_skel<'a>() -> NetworkDispatcherSkel<'a> {
        let mut skel = NetworkDispatcherSkel::default();
        skel.expect_progs().returning(generate_progs);
        skel.expect_maps_mut().returning(generate_maps_mut);
        skel.expect_maps().returning(generate_maps);
        skel
    }

    fn generate_progs() -> NetworkDispatcherProgs {
        let mut progs = NetworkDispatcherProgs::default();
        progs
            .expect_tc_egress()
            .times(1)
            .returning(generate_program);
        progs
    }

    fn generate_program() -> Program {
        let mut prog = Program::default();
        prog.expect_as_fd().times(1).return_const(1);
        prog
    }

    fn generate_maps_mut() -> NetworkDispatcherMapsMut {
        let mut maps_mut = NetworkDispatcherMapsMut::default();
        maps_mut.expect_streams().returning(|| {
            let mut map = Map::default();
            map.expect_update().times(1).returning(|key, value, _| {
                let stream = Stream::from_bytes(value.try_into().unwrap()).unwrap();
                match key[0] {
                    0 => {
                        assert_eq!(stream.egress_priority, 0);
                        assert_eq!(stream.shifted_pcp, 0);
                        assert_eq!(stream.socket_token, 0);
                    }
                    1 => {
                        assert_eq!(stream.egress_priority, PRIORITY);
                        assert_eq!(stream.shifted_pcp, u16::from(PCP) << 13);
                        assert_eq!(stream.socket_token, TOKEN);
                    }
                    _ => panic!("Invalid stream_handle"),
                }
                Ok(())
            });
            map
        });

        maps_mut.expect_num_streams().returning(|| {
            let mut map = Map::default();
            map.expect_update()
                .times(1)
                .returning(|_key, _value, _| Ok(()));
            map
        });

        maps_mut.expect_stream_handles().returning(|| {
            let mut map = Map::default();
            map.expect_update().times(1).returning(|key, value, _| {
                let stream_id_bytes = STREAM_ID.to_bytes();
                assert_eq!(key, stream_id_bytes);
                assert_eq!(value, vec![1, 0]);
                Ok(())
            });
            map
        });

        maps_mut
    }

    fn generate_maps() -> NetworkDispatcherMaps {
        let mut maps = NetworkDispatcherMaps::default();

        maps.expect_stream_handles().returning(|| {
            let mut map = Map::default();
            map.expect_lookup()
                .times(1)
                .returning(|_key, _value| Ok(None));
            map
        });

        maps.expect_num_streams().returning(|| {
            let mut map = Map::default();
            map.expect_lookup()
                .returning(|_key, _value| Ok(Some(vec![1, 0])));
            map
        });

        maps.expect_streams().returning(|| {
            let mut map = Map::default();
            map.expect_info().returning(|| {
                Ok(MockMapInfo {
                    info: MockInnerMapInfo { max_entries: 100 },
                })
            });
            map
        });

        maps
    }

    #[test]
    fn test_happy() -> Result<()> {
        let mut dispatcher = BPFDispatcher {
            interfaces: HashMap::default(),
            generate_skel: Box::new(generate_skel_builder),
            nametoindex: Box::new(|interface| {
                assert_eq!(interface, INTERFACE);
                Ok(3)
            }),
            debug_output: false,
        };

        dispatcher.configure_stream(INTERFACE, &STREAM_ID, PRIORITY, PCP, Some(TOKEN))?;
        Ok(())
    }

    #[test]
    #[should_panic(expected = "interface not found")]
    fn test_interface_not_found() {
        let mut dispatcher = BPFDispatcher {
            interfaces: HashMap::default(),
            generate_skel: Box::new(generate_skel_builder),
            nametoindex: Box::new(|interface| {
                assert_eq!(interface, INTERFACE);
                Err(anyhow!("interface not found"))
            }),
            debug_output: false,
        };

        dispatcher
            .configure_stream(INTERFACE, &STREAM_ID, PRIORITY, PCP, Some(TOKEN))
            .unwrap();
    }
}
