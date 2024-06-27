// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::configuration::{Stream, StreamIdentification};
use anyhow::{anyhow, Context, Result};
use libbpf_rs::{MapFlags, XdpFlags};

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
    libbpf_rs::Xdp,
    std::os::fd::AsFd,
};

#[cfg(test)]
use crate::bpf::mocks as core_mocks;
#[cfg(test)]
mod mocks;
#[cfg(test)]
use {
    core_mocks::MockXdp as Xdp, mocks::MockDataPlaneSkel as DataPlaneSkel,
    mocks::MockDataPlaneSkelBuilder as DataPlaneSkelBuilder,
};

use crate::bpf::{find_or_add_stream, Attacher, SkelManager};
use crate::data_plane::DataPlane;

#[derive(Debug)]
struct XdpStream {
    handle: u16,
    outgoing_interface: u32,
}

impl XdpStream {
    fn to_bytes(&self) -> [u8; 6] {
        let mut result: [u8; 6] = [0; 6];
        result[0..2].copy_from_slice(&self.handle.to_ne_bytes()[..]); // 2 bytes
        result[2..6].copy_from_slice(&self.outgoing_interface.to_ne_bytes()[..]); // 4 bytes
        result
    }

    fn from_bytes(bytes: [u8; 6]) -> Result<Self> {
        Ok(Self {
            handle: u16::from_ne_bytes(
                bytes[0..2]
                    .try_into()
                    .map_err(|_e| anyhow!("Invalid byte number"))?,
            ),
            outgoing_interface: u32::from_ne_bytes(
                bytes[2..6]
                    .try_into()
                    .map_err(|_e| anyhow!("Invalid byte number"))?,
            ),
        })
    }
}

struct XdpStreamBuilder {
    stream: XdpStream,
}

impl XdpStreamBuilder {
    const fn new() -> Self {
        Self {
            stream: XdpStream {
                handle: 0,
                outgoing_interface: 0,
            },
        }
    }

    const fn handle(mut self, handle: u16) -> Self {
        self.stream.handle = handle;
        self
    }

    const fn outgoing_interface(mut self, interface_idx: u32) -> Self {
        self.stream.outgoing_interface = interface_idx;
        self
    }

    const fn build(self) -> XdpStream {
        self.stream
    }
}

type GenerateSkelCallback = Box<dyn FnMut() -> DataPlaneSkelBuilder + Send>;
type NameToIndexCallback = Box<dyn FnMut(&str) -> Result<i32> + Send>;

/// Installs eBPFs for packet handling
pub struct BpfDataPlane<'a> {
    skels: SkelManager<DataPlaneSkel<'a>>,
    nametoindex: NameToIndexCallback,
}

struct DataPlaneAttacher {
    generate_skel: GenerateSkelCallback,
    nametoindex: NameToIndexCallback,
    debug_output: bool,
}

impl DataPlane for BpfDataPlane<'_> {
    fn setup_stream(&mut self, stream_config: &Stream) -> Result<()> {
        let outgoing_interface =
            (self.nametoindex)(stream_config.outgoing_l2()?.outgoing_interface()?)?.try_into()?;

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
                )
                .context("Failed to find or add stream")?;

                let xdp_stream = XdpStreamBuilder::new()
                    .handle(stream_handle)
                    .outgoing_interface(outgoing_interface)
                    .build();

                update_stream_maps(skel, stream_identification, &xdp_stream)
                    .context("Failed to update stream maps")
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
        }
    }
}

fn nametoindex(interface: &str) -> Result<i32> {
    Ok(i32::try_from(nix::net::if_::if_nametoindex(interface)?)?)
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

        let mut skel = open_skel.load()?;

        let progs = skel.progs();

        let xdp = Xdp::new(progs.xdp_bridge().as_fd());
        xdp.attach(ifidx, XdpFlags::NONE)?;

        // configure default stream handling
        // the handle 0 is explicitly handled inside the BPF
        skel.maps_mut()
            .streams()
            .update(
                &[0; 8],
                &XdpStreamBuilder::new().handle(0).build().to_bytes(),
                MapFlags::ANY,
            )
            .context("Failed to configure initial default stream handling")?;

        // configure initial number of streams
        skel.maps_mut()
            .num_streams()
            .update(&0_u32.to_ne_bytes(), &1_u16.to_ne_bytes(), MapFlags::ANY)
            .context("Failed to set num_streams")?;

        Ok(skel)
    }
}

fn update_stream_maps(
    skel: &mut DataPlaneSkel<'_>,
    stream_identification: &StreamIdentification,
    xdp_stream: &XdpStream,
) -> Result<()> {
    let xdp_stream_bytes = xdp_stream.to_bytes();

    skel.maps_mut().streams().update(
        &stream_identification.to_bytes()?,
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
                    info: MockInnerMapInfo { max_entries: 100 },
                })
            });
            map.expect_lookup().returning(|_key, _flags| {
                Ok(Some(XdpStreamBuilder::new().build().to_bytes().into()))
            });
            map
        });

        maps
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
        };

        let mut stream_config = StreamBuilder::new()
            .identification(generate_stream_identification(3))
            .incoming_interface(INCOMING_INTERFACE.to_owned())
            .outgoing_l2(
                OutgoingL2Builder::new()
                    .outgoing_interface(OUTGOING_INTERFACE.to_owned())
                    .build(),
            )
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
        };

        let mut stream_config = StreamBuilder::new()
            .identification(generate_stream_identification(3))
            .incoming_interface(INCOMING_INTERFACE.to_owned())
            .outgoing_l2(
                OutgoingL2Builder::new()
                    .outgoing_interface(OUTGOING_INTERFACE.to_owned())
                    .build(),
            )
            .build();

        stream_config.fill_defaults().unwrap();

        data_plane.setup_stream(&stream_config).unwrap();
    }
}
