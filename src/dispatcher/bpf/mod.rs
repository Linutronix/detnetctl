// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Context, Result};
use libbpf_rs::{set_print, MapFlags, PrintLevel, TC_EGRESS};
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;

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
    shifted_pcp: u16,
    egress_priority: u32,
}

impl Stream {
    fn new(priority: u32, pcp: u8, is_protected: bool) -> Self {
        Self {
            restrictions: u8::from(is_protected),
            shifted_pcp: u16::from(pcp) << 13,
            egress_priority: priority,
        }
    }

    fn pcp(&self) -> Result<u8> {
        (self.shifted_pcp >> 13)
            .try_into()
            .map_err(|_e| anyhow!("Cannot properly shift PCP"))
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 7] {
        let mut result: [u8; 7] = [0; 7];
        result[0] = self.restrictions;
        result[1..3].copy_from_slice(&self.shifted_pcp.to_ne_bytes()[..]);
        result[3..7].copy_from_slice(&self.egress_priority.to_ne_bytes()[..]);
        result
    }

    pub fn from_bytes(bytes: [u8; 7]) -> Result<Self> {
        Ok(Self {
            restrictions: bytes[0],
            shifted_pcp: u16::from_ne_bytes(
                bytes[1..3]
                    .try_into()
                    .map_err(|_e| anyhow!("Invalid byte number"))?,
            ),
            egress_priority: u32::from_ne_bytes(
                bytes[3..7]
                    .try_into()
                    .map_err(|_e| anyhow!("Invalid byte number"))?,
            ),
        })
    }
}

impl StreamIdentification {
    /// Convert into fixed-size array
    ///
    /// # Errors
    /// Currently returns error if any of the attributes are None
    pub fn to_bytes(&self) -> Result<[u8; 8]> {
        let destination_address = self.destination_address.ok_or_else(|| {
            anyhow!("Streams without destination address can currently not be handled")
        })?;
        let vlan_identifier = self
            .vlan_identifier
            .ok_or_else(|| anyhow!("Streams without VLAN ID can currently not be handled"))?;

        let mut result: [u8; 8] = [0; 8];
        result[0..6].copy_from_slice(destination_address.as_bytes());
        result[6..8].copy_from_slice(&vlan_identifier.to_ne_bytes());
        Ok(result)
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

impl Dispatcher for BPFDispatcher<'_> {
    fn configure_stream(
        &mut self,
        interface: &str,
        stream_identification: &StreamIdentification,
        priority: u32,
        pcp: Option<u8>,
        cgroup: Option<Arc<Path>>,
    ) -> Result<()> {
        self.with_interface(interface, |iface| {
            iface
                .configure_stream(stream_identification, priority, pcp, cgroup)
                .context("Failed to configure stream")
        })
    }

    fn protect_stream(
        &mut self,
        interface: &str,
        stream_identification: &StreamIdentification,
        cgroup: Option<Arc<Path>>,
    ) -> Result<()> {
        self.with_interface(interface, |iface| {
            iface
                .protect_stream(stream_identification, cgroup)
                .context("Failed to protect stream")
        })
    }

    fn configure_best_effort(
        &mut self,
        interface: &str,
        priority: u32,
        cgroup: Option<Arc<Path>>,
    ) -> Result<()> {
        self.with_interface(interface, |iface| {
            iface
                .configure_best_effort(priority, cgroup)
                .context("Failed to configure best effort")
        })
    }
}

impl BPFDispatcher<'_> {
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
        f: impl FnOnce(&mut BPFInterface<'_>) -> Result<()>,
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
        skel.maps_mut()
            .streams()
            .update(
                &0_u32.to_ne_bytes(),
                &Stream::new(0, 0, false).to_bytes(),
                MapFlags::ANY,
            )
            .context("Failed to configure initial best-effort stream")?;

        skel.maps_mut()
            .num_streams()
            .update(&0_u32.to_ne_bytes(), &1_u16.to_ne_bytes(), MapFlags::ANY)
            .context("Failed to set num_streams")?;

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

impl Default for BPFDispatcher<'_> {
    fn default() -> Self {
        Self::new(false)
    }
}

impl BPFInterface<'_> {
    pub fn configure_stream(
        &mut self,
        stream_identification: &StreamIdentification,
        priority: u32,
        pcp: Option<u8>,
        cgroup: Option<Arc<Path>>,
    ) -> Result<()> {
        let stream_id_bytes = stream_identification.to_bytes()?;

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

        let pcp = pcp.ok_or_else(|| anyhow!("PCP configuration required for TSN dispatcher"))?;

        self.update_stream_maps(u32::from(stream_handle), priority, pcp, cgroup)?;

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

    pub fn protect_stream(
        &mut self,
        stream_identification: &StreamIdentification,
        cgroup: Option<Arc<Path>>,
    ) -> Result<()> {
        let stream_id_bytes = stream_identification.to_bytes()?;

        let stream_handle: u32 = u16::from_ne_bytes(
            self.skel
                .maps()
                .stream_handles()
                .lookup(&stream_id_bytes, MapFlags::ANY)?
                .ok_or_else(|| anyhow!("Cannot find stream for identification"))?
                .try_into()
                .map_err(|_e| anyhow!("Invalid byte number"))?,
        )
        .into();

        let stream = Stream::from_bytes(
            self.skel
                .maps()
                .streams()
                .lookup(&stream_handle.to_ne_bytes(), MapFlags::ANY)?
                .ok_or_else(|| anyhow!("Cannot find stream for handle"))?
                .try_into()
                .map_err(|_e| anyhow!("Invalid byte number"))?,
        )?;

        self.update_stream_maps(stream_handle, stream.egress_priority, stream.pcp()?, cgroup)?;

        Ok(())
    }

    pub fn configure_best_effort(
        &mut self,
        priority: u32,
        cgroup: Option<Arc<Path>>,
    ) -> Result<()> {
        self.update_stream_maps(0, priority, 0 /* best-effort PCP */, cgroup)
    }

    fn update_stream_maps(
        &mut self,
        stream_handle: u32,
        priority: u32,
        pcp: u8,
        cgroup: Option<Arc<Path>>,
    ) -> Result<()> {
        let mut is_protected = false;
        if let Some(cgroup) = cgroup {
            is_protected = true;
            let full_cgroup_path =
                Path::new("/sys/fs/cgroup").join(cgroup.strip_prefix("/").unwrap_or(&cgroup));
            let cgroup_file = File::open(full_cgroup_path)?;
            let cgroup_fd = cgroup_file.as_raw_fd();

            self.skel.maps_mut().stream_cgroups().update(
                &stream_handle.to_ne_bytes(),
                &cgroup_fd.to_ne_bytes(),
                MapFlags::ANY,
            )?;
        }

        self.skel.maps_mut().streams().update(
            &stream_handle.to_ne_bytes(),
            &Stream::new(priority, pcp, is_protected).to_bytes(),
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
    use regex::Regex;
    use std::fs;
    use std::io;
    use std::io::BufRead;
    use std::path::Path;
    use std::process;
    use std::sync::Arc;

    const INTERFACE: &str = "eth12";
    const PCP: u8 = 3;
    const PRIORITY: u32 = 6;
    const STREAM_ID: StreamIdentification = StreamIdentification {
        destination_address: Some(MacAddress::new([0xab, 0xcb, 0xcb, 0xcb, 0xcb, 0xcb])),
        vlan_identifier: Some(3),
    };
    const STREAM_ID2: StreamIdentification = StreamIdentification {
        destination_address: STREAM_ID.destination_address,
        vlan_identifier: Some(7),
    };

    fn generate_skel_builder(cgroup: Arc<Path>) -> NetworkDispatcherSkelBuilder {
        let mut builder = NetworkDispatcherSkelBuilder::default();
        builder
            .expect_open()
            .times(1)
            .returning(move || Ok(generate_open_skel(cgroup.clone())));
        builder
    }

    fn generate_open_skel(cgroup: Arc<Path>) -> OpenNetworkDispatcherSkel {
        let mut open_skel = OpenNetworkDispatcherSkel::default();
        open_skel
            .expect_load()
            .times(1)
            .returning(move || Ok(generate_skel(cgroup.clone())));
        open_skel.expect_rodata().times(1).returning(|| {
            mocks::network_dispatcher_rodata_types::rodata {
                debug_output: false,
            }
        });
        open_skel
    }

    fn generate_skel<'a>(cgroup: Arc<Path>) -> NetworkDispatcherSkel<'a> {
        let mut skel = NetworkDispatcherSkel::default();
        skel.expect_progs().returning(generate_progs);
        skel.expect_maps_mut()
            .returning(move || generate_maps_mut(cgroup.clone()));
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

    fn generate_maps_mut(cgroup: Arc<Path>) -> NetworkDispatcherMapsMut {
        let mut maps_mut = NetworkDispatcherMapsMut::default();
        maps_mut.expect_streams().returning(|| {
            let mut map = Map::default();
            map.expect_update().times(1).returning(|key, value, _| {
                let stream = Stream::from_bytes(value.try_into().unwrap()).unwrap();
                match key[0] {
                    0 => {
                        assert_eq!(stream.egress_priority, 0);
                        assert_eq!(stream.shifted_pcp, 0);
                    }
                    1 => {
                        assert_eq!(stream.egress_priority, PRIORITY);
                        assert_eq!(stream.shifted_pcp, u16::from(PCP) << 13);
                    }
                    _ => panic!("Invalid stream_handle"),
                }
                Ok(())
            });
            map
        });

        maps_mut.expect_stream_cgroups().returning(move || {
            let mut map = Map::default();
            let cgroup = cgroup.clone();
            map.expect_update()
                .times(1)
                .returning(move |key, value, _| {
                    assert_eq!(key, 1_u32.to_ne_bytes());

                    let raw_fd = u32::from_ne_bytes(
                        value
                            .try_into()
                            .map_err(|_e| anyhow!("Invalid byte number"))?,
                    );
                    let captured_cgroup =
                        Path::new(&format!("/proc/self/fd/{raw_fd}")).read_link()?;
                    let full_cgroup_path = Path::new("/sys/fs/cgroup")
                        .join(cgroup.strip_prefix("/").unwrap_or(&cgroup));
                    assert_eq!(captured_cgroup, *full_cgroup_path);
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
                let stream_id_bytes = STREAM_ID.to_bytes().unwrap();
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
            map.expect_lookup().times(1).returning(|key, _flags| {
                if key == STREAM_ID.to_bytes().unwrap() {
                    Ok(Some(vec![1, 0]))
                } else {
                    Ok(None)
                }
            });
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
            map.expect_lookup()
                .returning(|_key, _flags| Ok(Some(Stream::new(6, 3, false).to_bytes().into())));
            map
        });

        maps
    }

    #[test]
    fn test_configure_stream_happy() -> Result<()> {
        let cgroup = get_cgroup(process::id())?;
        let cgroup_path: Arc<Path> = Path::new(&cgroup).into();

        let mut dispatcher = BPFDispatcher {
            interfaces: HashMap::default(),
            generate_skel: Box::new(move || generate_skel_builder(cgroup_path.clone())),
            nametoindex: Box::new(|interface| {
                assert_eq!(interface, INTERFACE);
                Ok(3)
            }),
            debug_output: false,
        };

        dispatcher.configure_stream(
            INTERFACE,
            &STREAM_ID,
            PRIORITY,
            Some(PCP),
            Some(Path::new(&cgroup).into()),
        )?;
        Ok(())
    }

    fn get_cgroup(pid: u32) -> Result<String> {
        let lines = read_lines(format!("/proc/{pid}/cgroup"))?;
        let re = Regex::new(r"0::([^ ]*)")?;
        for line in lines.flatten() {
            if let Some(caps) = re.captures(&line) {
                if let Some(m) = caps.get(1) {
                    return Ok(m.as_str().to_owned());
                }
            }
        }

        Err(anyhow!("cgroup not found"))
    }

    fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where
        P: AsRef<Path>,
    {
        let file = fs::File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    }

    #[test]
    #[should_panic(expected = "interface not found")]
    fn test_configure_stream_interface_not_found() {
        let cgroup = get_cgroup(process::id()).unwrap();
        let cgroup_path: Arc<Path> = Path::new(&cgroup).into();

        let mut dispatcher = BPFDispatcher {
            interfaces: HashMap::default(),
            generate_skel: Box::new(move || generate_skel_builder(cgroup_path.clone())),
            nametoindex: Box::new(|interface| {
                assert_eq!(interface, INTERFACE);
                Err(anyhow!("interface not found"))
            }),
            debug_output: false,
        };

        dispatcher
            .configure_stream(
                INTERFACE,
                &STREAM_ID,
                PRIORITY,
                Some(PCP),
                Some(Path::new(&cgroup).into()),
            )
            .unwrap();
    }

    #[test]
    fn test_protect_happy() -> Result<()> {
        let cgroup = get_cgroup(process::id())?;
        let cgroup_path: Arc<Path> = Path::new(&cgroup).into();

        let mut dispatcher = BPFDispatcher {
            interfaces: HashMap::default(),
            generate_skel: Box::new(move || generate_skel_builder(cgroup_path.clone())),
            nametoindex: Box::new(|interface| {
                assert_eq!(interface, INTERFACE);
                Ok(3)
            }),
            debug_output: false,
        };

        dispatcher.protect_stream(INTERFACE, &STREAM_ID, Some(Path::new(&cgroup).into()))?;
        Ok(())
    }

    #[test]
    #[should_panic(expected = "Cannot find stream for identification")]
    fn test_protect_stream_missing() {
        let cgroup = get_cgroup(process::id()).unwrap();
        let cgroup_path: Arc<Path> = Path::new(&cgroup).into();

        let mut dispatcher = BPFDispatcher {
            interfaces: HashMap::default(),
            generate_skel: Box::new(move || generate_skel_builder(cgroup_path.clone())),
            nametoindex: Box::new(|interface| {
                assert_eq!(interface, INTERFACE);
                Ok(3)
            }),
            debug_output: false,
        };

        dispatcher
            .protect_stream(INTERFACE, &STREAM_ID2, Some(Path::new(&cgroup).into()))
            .unwrap();
    }
}
