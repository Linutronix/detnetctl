// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::configuration::{OutgoingL2, Stream};
use anyhow::{anyhow, Context, Result};
use flagset::{flags, FlagSet};
use libbpf_rs::libbpf_sys;
use libbpf_rs::{MapFlags, MapType, XdpFlags};
use std::mem::size_of;
use std::os::fd::AsRawFd;

#[cfg(not(test))]
#[allow(
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction,
    unreachable_pub
)] // this is generated code
mod data_plane_bpf {
    include!(concat!(env!("OUT_DIR"), "/data_plane.skel.rs"));
}
#[cfg(not(test))]
use {
    data_plane_bpf::DataPlaneSkel,
    data_plane_bpf::DataPlaneSkelBuilder,
    libbpf_rs::skel::{OpenSkel, SkelBuilder},
    libbpf_rs::{MapHandle, Xdp},
    std::os::fd::AsFd,
};

#[cfg(test)]
use crate::bpf::mocks as core_mocks;
#[cfg(test)]
mod mocks;
#[cfg(test)]
use {
    core_mocks::MockXdp as Xdp, mocks::MockDataPlaneSkel as DataPlaneSkel,
    mocks::MockDataPlaneSkelBuilder as DataPlaneSkelBuilder, mocks::MockMapHandle as MapHandle,
};

use crate::bpf::{find_or_add_stream, Attacher, SkelManager};
use crate::data_plane::DataPlane;

const MAX_REPLICATIONS: u32 = 6;

flags! {
    enum XdpStreamFlags: u8 {
        SequenceGeneration = 0x1,
    }
}

#[derive(Debug)]
struct XdpStream {
    handle: u16,
    flags: FlagSet<XdpStreamFlags>,
}

impl XdpStream {
    fn to_bytes(&self) -> [u8; 6] {
        let mut result: [u8; 6] = [0; 6];
        result[0..2].copy_from_slice(&self.handle.to_ne_bytes()[..]); // 2 bytes
        result[2] = self.flags.bits(); // 1 byte
        result
    }

    fn from_bytes(bytes: [u8; 6]) -> Result<Self> {
        Ok(Self {
            handle: u16::from_ne_bytes(
                bytes[0..2]
                    .try_into()
                    .map_err(|_e| anyhow!("Invalid byte number"))?,
            ),
            flags: FlagSet::new(bytes[2]).map_err(|e| anyhow!("Invalid bit {e}"))?,
        })
    }
}

struct XdpStreamBuilder {
    stream: XdpStream,
}

impl XdpStreamBuilder {
    fn new() -> Self {
        Self {
            stream: XdpStream {
                handle: 0,
                flags: FlagSet::default(),
            },
        }
    }

    const fn handle(mut self, handle: u16) -> Self {
        self.stream.handle = handle;
        self
    }

    fn sequence_generation(mut self, enable: bool) -> Self {
        if enable {
            self.stream.flags |= XdpStreamFlags::SequenceGeneration;
        } else {
            self.stream.flags &= !XdpStreamFlags::SequenceGeneration;
        }
        self
    }

    const fn build(self) -> XdpStream {
        self.stream
    }
}

type GenerateSkelCallback = Box<dyn FnMut() -> DataPlaneSkelBuilder + Send>;
type NameToIndexCallback = Box<dyn FnMut(&str) -> Result<i32> + Send>;
type CreateDevmapCallback = Box<dyn FnMut() -> Result<MapHandle> + Send>;

/// Installs eBPFs for packet handling
pub struct BpfDataPlane<'a> {
    skels: SkelManager<DataPlaneSkel<'a>>,
    nametoindex: NameToIndexCallback,
    create_devmap: CreateDevmapCallback,
}

struct DataPlaneAttacher {
    generate_skel: GenerateSkelCallback,
    nametoindex: NameToIndexCallback,
    debug_output: bool,
}

impl DataPlane for BpfDataPlane<'_> {
    fn setup_stream(&mut self, stream_config: &Stream) -> Result<()> {
        let stream_identification = stream_config.identification()?;

        self.skels
            .with_interface(stream_config.incoming_interface()?, |skel| {
                let stream_handle = find_or_add_stream(
                    skel.maps().streams(),
                    skel.maps().num_streams(),
                    stream_identification,
                    |s| {
                        Ok(XdpStream::from_bytes(
                            s.try_into().map_err(|_e| anyhow!("Invalid byte number"))?,
                        )?
                        .handle)
                    },
                )?;

                let outgoing_l2 = stream_config.outgoing_l2()?;

                let xdp_stream = XdpStreamBuilder::new()
                    .handle(stream_handle)
                    .sequence_generation(outgoing_l2.len() > 1)
                    .build();

                update_stream_maps(
                    skel,
                    u32::from(stream_handle),
                    &xdp_stream,
                    outgoing_l2,
                    &mut self.nametoindex,
                    &mut self.create_devmap,
                )
            })
            .context("Failed to configure stream")
    }
}

impl BpfDataPlane<'_> {
    /// Create a new `BpfDataPlane`
    pub fn new(debug_output: bool) -> Self {
        Self {
            nametoindex: Box::new(nametoindex),
            skels: SkelManager::new(Box::new(DataPlaneAttacher {
                generate_skel: Box::new(DataPlaneSkelBuilder::default),
                nametoindex: Box::new(nametoindex),
                debug_output,
            })),
            create_devmap: Box::new(create_devmap),
        }
    }
}

fn nametoindex(interface: &str) -> Result<i32> {
    Ok(i32::try_from(nix::net::if_::if_nametoindex(interface)?)?)
}

fn create_devmap() -> Result<MapHandle> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>().try_into()?,
        map_flags: libbpf_sys::BPF_ANY,
        btf_fd: 0,
        btf_key_type_id: 0,
        btf_value_type_id: 0,
        btf_vmlinux_value_type_id: 0,
        inner_map_fd: 0,
        map_extra: 0,
        numa_node: 0,
        map_ifindex: 0,
        ..Default::default()
    };

    Ok(MapHandle::create::<&str>(
        MapType::Devmap,
        None,
        4,
        8,
        MAX_REPLICATIONS,
        &opts,
    )?)
}

impl Default for BpfDataPlane<'_> {
    fn default() -> Self {
        Self::new(false)
    }
}

impl<'a> Attacher<DataPlaneSkel<'a>> for DataPlaneAttacher {
    fn attach_interface(&mut self, interface: &str) -> Result<DataPlaneSkel<'a>> {
        let ifidx = (self.nametoindex)(interface)?;

        let skel_builder = (self.generate_skel)();
        let mut open_skel = skel_builder.open()?;
        open_skel.rodata_mut().debug_output = self.debug_output;

        let skel = open_skel.load()?;

        let progs = skel.progs();

        let xdp = Xdp::new(progs.xdp_bridge().as_fd());
        xdp.attach(ifidx, XdpFlags::NONE)?;

        Ok(skel)
    }
}

fn update_stream_maps(
    skel: &mut DataPlaneSkel<'_>,
    stream_handle: u32,
    xdp_stream: &XdpStream,
    outgoing_l2: &[OutgoingL2],
    nametoindex: &mut NameToIndexCallback,
    create_devmap: &mut CreateDevmapCallback,
) -> Result<()> {
    let redirect_interfaces = create_devmap()?;

    for (i, l2) in outgoing_l2.iter().enumerate() {
        let ifidx = (nametoindex)(l2.outgoing_interface()?)?;
        redirect_interfaces.update(&i.to_ne_bytes(), &ifidx.to_ne_bytes(), MapFlags::ANY)?;
    }

    skel.maps_mut().redirect_map().update(
        &stream_handle.to_ne_bytes(),
        &redirect_interfaces.as_fd().as_raw_fd().to_ne_bytes(),
        MapFlags::ANY,
    )?;

    let initial_seqgen = vec![
        0;
        skel.maps()
            .seqgen_map()
            .info()?
            .info
            .value_size
            .try_into()?
    ];
    skel.maps_mut().seqgen_map().update(
        &stream_handle.to_ne_bytes(),
        &initial_seqgen,
        MapFlags::NO_EXIST, // keep existing state
    )?;

    let xdp_stream_bytes = xdp_stream.to_bytes();

    skel.maps_mut().streams().update(
        &stream_handle.to_ne_bytes(),
        &xdp_stream_bytes,
        MapFlags::ANY,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::StreamIdentification;
    use crate::configuration::{
        FillDefaults, OutgoingL2Builder, StreamBuilder, StreamIdentificationBuilder,
    };
    use anyhow::anyhow;
    use core_mocks::MockMap as Map;
    use core_mocks::MockXdpProgram as Program;
    use core_mocks::{MockInnerMapInfo, MockMapInfo};
    use eui48::MacAddress;
    use mocks::MockDataPlaneMaps as DataPlaneMaps;
    use mocks::MockDataPlaneMapsMut as DataPlaneMapsMut;
    use mocks::MockDataPlaneProgs as DataPlaneProgs;
    use mocks::MockMapHandle as MapHandle;
    use mocks::MockOpenDataPlaneSkel as OpenDataPlaneSkel;
    use std::os::fd::BorrowedFd;

    const INCOMING_INTERFACE: &str = "eth1";
    const OUTGOING_INTERFACE: &str = "eth12";
    const DESTINATION: MacAddress = MacAddress::new([0xab, 0xcb, 0xcb, 0xcb, 0xcb, 0xcb]);

    fn generate_stream_identification(vid: u16) -> StreamIdentification {
        StreamIdentificationBuilder::new()
            .destination_address(DESTINATION)
            .vid(vid)
            .build()
    }

    fn generate_skel_builder() -> DataPlaneSkelBuilder {
        let mut builder = DataPlaneSkelBuilder::default();
        builder
            .expect_open()
            .times(1)
            .returning(move || Ok(generate_open_skel()));
        builder
    }

    fn generate_open_skel() -> OpenDataPlaneSkel {
        let mut open_skel = OpenDataPlaneSkel::default();
        open_skel
            .expect_load()
            .times(1)
            .returning(move || Ok(generate_skel()));
        open_skel
            .expect_rodata_mut()
            .returning(|| mocks::bpf_rodata_types::rodata {
                debug_output: false,
            });
        open_skel
    }

    fn generate_skel<'a>() -> DataPlaneSkel<'a> {
        let mut skel = DataPlaneSkel::default();
        skel.expect_progs().returning(generate_progs);
        skel.expect_maps_mut().returning(generate_maps_mut);
        skel.expect_maps().returning(generate_maps);
        skel
    }

    fn generate_progs() -> DataPlaneProgs {
        let mut progs = DataPlaneProgs::default();
        progs.expect_xdp_bridge().returning(generate_program);
        progs
    }

    fn generate_program() -> Program {
        let mut prog = Program::default();
        // SAFETY: Only for testing
        unsafe {
            prog.expect_as_fd()
                .times(1)
                .return_const(BorrowedFd::borrow_raw(1));
        }
        prog
    }

    fn generate_maps_mut() -> DataPlaneMapsMut {
        let mut maps_mut = DataPlaneMapsMut::default();
        maps_mut.expect_streams().returning(|| {
            let mut map = Map::default();
            map.expect_update()
                .times(1)
                .returning(|_key, _value, _| Ok(()));
            map
        });

        maps_mut.expect_num_streams().returning(|| {
            let mut map = Map::default();
            map.expect_update()
                .times(1)
                .returning(|_key, _value, _| Ok(()));
            map
        });

        maps_mut.expect_redirect_map().returning(|| {
            let mut map = Map::default();
            map.expect_update().returning(|_key, _value, _| Ok(()));
            map
        });

        maps_mut.expect_seqgen_map().returning(|| {
            let mut map = Map::default();
            map.expect_update().returning(|_key, _value, _| Ok(()));
            map
        });

        maps_mut
    }

    fn generate_maps() -> DataPlaneMaps {
        let mut maps = DataPlaneMaps::default();

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
                    info: MockInnerMapInfo {
                        max_entries: 100,
                        value_size: 8,
                    },
                })
            });
            map.expect_lookup().returning(|_key, _flags| {
                Ok(Some(XdpStreamBuilder::new().build().to_bytes().into()))
            });
            map
        });

        maps.expect_seqgen_map().returning(|| {
            let mut map = Map::default();
            map.expect_info().returning(|| {
                Ok(MockMapInfo {
                    info: MockInnerMapInfo {
                        max_entries: 100,
                        value_size: 8,
                    },
                })
            });
            map
        });

        maps
    }

    fn create_devmap() -> MapHandle {
        let mut handle = MapHandle::default();
        handle.expect_update().returning(|_key, _value, _| Ok(()));
        handle.expect_as_fd().returning(||
                                        // SAFETY: Only testing
                                        unsafe {
                                            BorrowedFd::borrow_raw(0)
                                        });
        handle
    }

    #[test]
    fn test_setup_happy() -> Result<()> {
        let mut data_plane = BpfDataPlane {
            nametoindex: Box::new(|_interface| Ok(3)),
            skels: SkelManager::new(Box::new(DataPlaneAttacher {
                generate_skel: Box::new(generate_skel_builder),
                nametoindex: Box::new(|_interface| Ok(3)),
                debug_output: false,
            })),
            create_devmap: Box::new(|| Ok(create_devmap())),
        };

        let mut stream_config = StreamBuilder::new()
            .identification(generate_stream_identification(3))
            .incoming_interface(INCOMING_INTERFACE.to_owned())
            .outgoing_l2(vec![OutgoingL2Builder::new()
                .outgoing_interface(OUTGOING_INTERFACE.to_owned())
                .build()])
            .build();

        stream_config.fill_defaults()?;

        data_plane.setup_stream(&stream_config)?;
        Ok(())
    }

    #[test]
    #[should_panic(expected = "interface not found")]
    fn test_setup_interface_not_found() {
        let mut data_plane = BpfDataPlane {
            nametoindex: Box::new(|_interface| Err(anyhow!("interface not found"))),
            skels: SkelManager::new(Box::new(DataPlaneAttacher {
                generate_skel: Box::new(generate_skel_builder),
                nametoindex: Box::new(|_interface| Err(anyhow!("interface not found"))),
                debug_output: false,
            })),
            create_devmap: Box::new(|| Ok(create_devmap())),
        };

        let mut stream_config = StreamBuilder::new()
            .identification(generate_stream_identification(3))
            .incoming_interface(INCOMING_INTERFACE.to_owned())
            .outgoing_l2(vec![OutgoingL2Builder::new()
                .outgoing_interface(OUTGOING_INTERFACE.to_owned())
                .build()])
            .build();

        stream_config.fill_defaults().unwrap();

        data_plane.setup_stream(&stream_config).unwrap();
    }
}
