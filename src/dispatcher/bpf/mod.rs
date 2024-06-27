// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Context, Result};
use eui48::MacAddress;
use libbpf_rs::{MapFlags, TC_EGRESS};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;

#[cfg(not(test))]
#[allow(
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction,
    unreachable_pub
)] // this is generated code
mod dispatcher {
    include!(concat!(env!("OUT_DIR"), "/dispatcher.skel.rs"));
}
#[cfg(not(test))]
use {
    dispatcher::DispatcherSkel,
    dispatcher::DispatcherSkelBuilder,
    libbpf_rs::skel::{OpenSkel, SkelBuilder},
    libbpf_rs::TcHookBuilder,
    std::os::fd::AsFd,
};

#[cfg(test)]
mod mocks;
#[cfg(test)]
use {
    crate::bpf::mocks::MockTcHookBuilder as TcHookBuilder,
    mocks::MockDispatcherSkel as DispatcherSkel,
    mocks::MockDispatcherSkelBuilder as DispatcherSkelBuilder,
};

use crate::bpf::{find_or_add_stream, Attacher, SkelManager};
use crate::configuration::{StreamIdentification, StreamIdentificationBuilder};
use crate::dispatcher::Dispatcher;

#[derive(Debug)]
struct Stream {
    handle: u16,
    restrictions: u8,
    shifted_pcp: u16,
    egress_priority: u32,
}

impl Stream {
    fn new(handle: u16, priority: u32, pcp: u8, is_protected: bool) -> Self {
        Self {
            handle,
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
    fn to_bytes(&self) -> [u8; 9] {
        let mut result: [u8; 9] = [0; 9];
        result[0..2].copy_from_slice(&self.handle.to_ne_bytes()[..]);
        result[2] = self.restrictions;
        result[3..5].copy_from_slice(&self.shifted_pcp.to_ne_bytes()[..]);
        result[5..9].copy_from_slice(&self.egress_priority.to_ne_bytes()[..]);
        result
    }

    fn from_bytes(bytes: [u8; 9]) -> Result<Self> {
        Ok(Self {
            handle: u16::from_ne_bytes(
                bytes[0..2]
                    .try_into()
                    .map_err(|_e| anyhow!("Invalid byte number"))?,
            ),
            restrictions: bytes[2],
            shifted_pcp: u16::from_ne_bytes(
                bytes[3..5]
                    .try_into()
                    .map_err(|_e| anyhow!("Invalid byte number"))?,
            ),
            egress_priority: u32::from_ne_bytes(
                bytes[5..9]
                    .try_into()
                    .map_err(|_e| anyhow!("Invalid byte number"))?,
            ),
        })
    }
}

type GenerateSkelCallback = Box<dyn FnMut() -> DispatcherSkelBuilder + Send>;
type NameToIndexCallback = Box<dyn FnMut(&str) -> Result<i32> + Send>;

/// Installs eBPFs to dispatcher the network to prevent interference of real-time communication
pub struct BPFDispatcher<'a> {
    skels: SkelManager<DispatcherSkel<'a>>,
}

struct DispatcherAttacher {
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
        self.skels
            .with_interface(interface, |skel| {
                let stream_handle = find_or_add_stream(
                    skel.maps().streams(),
                    skel.maps().num_streams(),
                    stream_identification,
                    |s| {
                        Ok(Stream::from_bytes(
                            s.try_into().map_err(|_e| anyhow!("Invalid byte number"))?,
                        )?
                        .handle)
                    },
                )?;

                let pcp =
                    pcp.ok_or_else(|| anyhow!("PCP configuration required for TSN dispatcher"))?;

                update_stream_maps(
                    skel,
                    stream_identification,
                    stream_handle,
                    priority,
                    pcp,
                    cgroup,
                )?;

                Ok(())
            })
            .context("Failed to configure stream")
    }

    fn protect_stream(
        &mut self,
        interface: &str,
        stream_identification: &StreamIdentification,
        cgroup: Option<Arc<Path>>,
    ) -> Result<()> {
        self.skels
            .with_interface(interface, |skel| {
                let stream_id_bytes = stream_identification.to_bytes()?;

                let stream = Stream::from_bytes(
                    skel.maps()
                        .streams()
                        .lookup(&stream_id_bytes, MapFlags::ANY)?
                        .ok_or_else(|| anyhow!("Cannot find stream for identification"))?
                        .try_into()
                        .map_err(|_e| anyhow!("Invalid byte number"))?,
                )?;

                update_stream_maps(
                    skel,
                    stream_identification,
                    stream.handle,
                    stream.egress_priority,
                    stream.pcp()?,
                    cgroup,
                )
            })
            .context("Failed to protect stream")
    }

    fn configure_best_effort(
        &mut self,
        interface: &str,
        priority: u32,
        cgroup: Option<Arc<Path>>,
    ) -> Result<()> {
        self.skels
            .with_interface(interface, |skel| {
                let stream_id = StreamIdentificationBuilder::new()
                    .destination_address(MacAddress::new([0; 6]))
                    .vid(0)
                    .build();
                update_stream_maps(
                    skel, &stream_id, 0, priority, 0, /* best-effort PCP */
                    cgroup,
                )
            })
            .context("Failed to configure best effort")
    }
}

impl BPFDispatcher<'_> {
    /// Create a new `BPFDispatcher`
    pub fn new(debug_output: bool) -> Self {
        BPFDispatcher {
            skels: SkelManager::new(Box::new(DispatcherAttacher {
                generate_skel: Box::new(DispatcherSkelBuilder::default),
                nametoindex: Box::new(|interface| {
                    Ok(i32::try_from(nix::net::if_::if_nametoindex(interface)?)?)
                }),
                debug_output,
            })),
        }
    }
}

impl Default for BPFDispatcher<'_> {
    fn default() -> Self {
        Self::new(false)
    }
}

impl<'a> Attacher<DispatcherSkel<'a>> for DispatcherAttacher {
    fn attach_interface(&mut self, interface: &str) -> Result<DispatcherSkel<'a>> {
        let skel_builder = (self.generate_skel)();
        let mut open_skel = skel_builder.open()?;
        open_skel.rodata_mut().debug_output = self.debug_output;

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
                &Stream::new(0, 0, 0, false).to_bytes(),
                MapFlags::ANY,
            )
            .context("Failed to configure initial best-effort stream")?;

        skel.maps_mut()
            .num_streams()
            .update(&0_u32.to_ne_bytes(), &1_u16.to_ne_bytes(), MapFlags::ANY)
            .context("Failed to set num_streams")?;

        Ok(skel)
    }
}

fn update_stream_maps(
    skel: &mut DispatcherSkel<'_>,
    stream_identification: &StreamIdentification,
    stream_handle: u16,
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

        skel.maps_mut().stream_cgroups().update(
            &u32::from(stream_handle).to_ne_bytes(),
            &cgroup_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;
    }

    skel.maps_mut().streams().update(
        &stream_identification.to_bytes()?,
        &Stream::new(stream_handle, priority, pcp, is_protected).to_bytes(),
        MapFlags::ANY,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::mocks::MockMap as Map;
    use crate::bpf::mocks::MockTcProgram as Program;
    use crate::bpf::mocks::{MockInnerMapInfo, MockMapInfo};
    use crate::configuration::StreamIdentificationBuilder;
    use anyhow::anyhow;
    use eui48::MacAddress;
    use mocks::MockDispatcherMaps as DispatcherMaps;
    use mocks::MockDispatcherMapsMut as DispatcherMapsMut;
    use mocks::MockDispatcherProgs as DispatcherProgs;
    use mocks::MockOpenDispatcherSkel as OpenDispatcherSkel;
    use regex::Regex;
    use std::io;
    use std::io::BufRead;
    use std::path::Path;
    use std::process;
    use std::sync::Arc;

    const INTERFACE: &str = "eth12";
    const PCP: u8 = 3;
    const PRIORITY: u32 = 6;
    const DESTINATION: MacAddress = MacAddress::new([0xab, 0xcb, 0xcb, 0xcb, 0xcb, 0xcb]);

    fn generate_stream_identification(vid: u16) -> StreamIdentification {
        StreamIdentificationBuilder::new()
            .destination_address(DESTINATION)
            .vid(vid)
            .build()
    }

    fn generate_skel_builder(cgroup: Arc<Path>) -> DispatcherSkelBuilder {
        let mut builder = DispatcherSkelBuilder::default();
        builder
            .expect_open()
            .times(1)
            .returning(move || Ok(generate_open_skel(cgroup.clone())));
        builder
    }

    fn generate_open_skel(cgroup: Arc<Path>) -> OpenDispatcherSkel {
        let mut open_skel = OpenDispatcherSkel::default();
        open_skel
            .expect_load()
            .times(1)
            .returning(move || Ok(generate_skel(cgroup.clone())));
        open_skel
            .expect_rodata_mut()
            .times(1)
            .returning(|| mocks::bpf_rodata_types::rodata {
                debug_output: false,
            });
        open_skel
    }

    fn generate_skel<'a>(cgroup: Arc<Path>) -> DispatcherSkel<'a> {
        let mut skel = DispatcherSkel::default();
        skel.expect_progs().returning(generate_progs);
        skel.expect_maps_mut()
            .returning(move || generate_maps_mut(cgroup.clone()));
        skel.expect_maps().returning(generate_maps);
        skel
    }

    fn generate_progs() -> DispatcherProgs {
        let mut progs = DispatcherProgs::default();
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

    fn generate_maps_mut(cgroup: Arc<Path>) -> DispatcherMapsMut {
        let mut maps_mut = DispatcherMapsMut::default();
        maps_mut.expect_streams().returning(|| {
            let mut map = Map::default();
            map.expect_update().times(1).returning(|key, value, _| {
                let stream = Stream::from_bytes(value.try_into().unwrap()).unwrap();

                if key == [0; 4] {
                    assert_eq!(stream.egress_priority, 0);
                    assert_eq!(stream.shifted_pcp, 0);
                } else if key == generate_stream_identification(3).to_bytes()? {
                    assert_eq!(stream.egress_priority, PRIORITY);
                    assert_eq!(stream.shifted_pcp, u16::from(PCP) << 13);
                } else {
                    panic!("Invalid stream_handle {key:#?}");
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

        maps_mut
    }

    fn generate_maps() -> DispatcherMaps {
        let mut maps = DispatcherMaps::default();

        maps.expect_streams().returning(|| {
            let mut map = Map::default();
            map.expect_info().returning(|| {
                Ok(MockMapInfo {
                    info: MockInnerMapInfo { max_entries: 100 },
                })
            });
            map.expect_lookup().times(1).returning(|key, _flags| {
                if key == generate_stream_identification(3).to_bytes().unwrap() {
                    Ok(Some(Stream::new(1, 6, 3, false).to_bytes().into()))
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

        maps
    }

    #[test]
    fn test_configure_stream_happy() -> Result<()> {
        let cgroup = get_cgroup(process::id())?;
        let cgroup_path: Arc<Path> = Path::new(&cgroup).into();

        let mut dispatcher = BPFDispatcher {
            skels: SkelManager::new(Box::new(DispatcherAttacher {
                generate_skel: Box::new(move || generate_skel_builder(cgroup_path.clone())),
                nametoindex: Box::new(|interface| {
                    assert_eq!(interface, INTERFACE);
                    Ok(3)
                }),
                debug_output: false,
            })),
        };

        dispatcher.configure_stream(
            INTERFACE,
            &generate_stream_identification(3),
            PRIORITY,
            Some(PCP),
            Some(Path::new(&cgroup).into()),
        )?;
        Ok(())
    }

    fn get_cgroup(pid: u32) -> Result<String> {
        let lines = read_lines(format!("/proc/{pid}/cgroup"))?;
        let re = Regex::new(r"0::([^ ]*)")?;
        for line in lines.map_while(Result::ok) {
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
        let file = File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    }

    #[test]
    #[should_panic(expected = "interface not found")]
    fn test_configure_stream_interface_not_found() {
        let cgroup = get_cgroup(process::id()).unwrap();
        let cgroup_path: Arc<Path> = Path::new(&cgroup).into();

        let mut dispatcher = BPFDispatcher {
            skels: SkelManager::new(Box::new(DispatcherAttacher {
                generate_skel: Box::new(move || generate_skel_builder(cgroup_path.clone())),
                nametoindex: Box::new(|interface| {
                    assert_eq!(interface, INTERFACE);
                    Err(anyhow!("interface not found"))
                }),
                debug_output: false,
            })),
        };

        dispatcher
            .configure_stream(
                INTERFACE,
                &generate_stream_identification(3),
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
            skels: SkelManager::new(Box::new(DispatcherAttacher {
                generate_skel: Box::new(move || generate_skel_builder(cgroup_path.clone())),
                nametoindex: Box::new(|interface| {
                    assert_eq!(interface, INTERFACE);
                    Ok(3)
                }),
                debug_output: false,
            })),
        };

        dispatcher.protect_stream(
            INTERFACE,
            &generate_stream_identification(3),
            Some(Path::new(&cgroup).into()),
        )?;
        Ok(())
    }

    #[test]
    #[should_panic(expected = "Cannot find stream for identification")]
    fn test_protect_stream_missing() {
        let cgroup = get_cgroup(process::id()).unwrap();
        let cgroup_path: Arc<Path> = Path::new(&cgroup).into();

        let mut dispatcher = BPFDispatcher {
            skels: SkelManager::new(Box::new(DispatcherAttacher {
                generate_skel: Box::new(move || generate_skel_builder(cgroup_path.clone())),
                nametoindex: Box::new(|interface| {
                    assert_eq!(interface, INTERFACE);
                    Ok(3)
                }),
                debug_output: false,
            })),
        };

        dispatcher
            .protect_stream(
                INTERFACE,
                &generate_stream_identification(7),
                Some(Path::new(&cgroup).into()),
            )
            .unwrap();
    }
}
