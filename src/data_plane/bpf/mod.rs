// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::configuration::{Flow, PhysicalInterface, StreamIdentificationBuilder};
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
struct XdpFlow {
    handle: u16,
    outgoing_interface: u32,
}

impl XdpFlow {
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

struct XdpFlowBuilder {
    flow: XdpFlow,
}

impl XdpFlowBuilder {
    const fn new() -> Self {
        Self {
            flow: XdpFlow {
                handle: 0,
                outgoing_interface: 0,
            },
        }
    }

    const fn outgoing_interface(mut self, interface_idx: u32) -> Self {
        self.flow.outgoing_interface = interface_idx;
        self
    }

    const fn build(self) -> XdpFlow {
        self.flow
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
    fn setup_flow(
        &mut self,
        flow_config: &Flow,
        _interface_config: &PhysicalInterface,
    ) -> Result<()> {
        let xdp_flow = XdpFlowBuilder::new()
            .outgoing_interface(
                (self.nametoindex)(flow_config.next_hop()?.outgoing_interface()?)?.try_into()?,
            )
            .build();

        let stream_identification = flow_config.app()?.stream()?;

        self.skels
            .with_interface(flow_config.app()?.ingress_interface()?, |skel| {
                let stream_handle = find_or_add_stream(
                    skel.maps().streams(),
                    skel.maps().num_streams(),
                    stream_identification,
                    |s| {
                        Ok(XdpFlow::from_bytes(
                            s.try_into().map_err(|_e| anyhow!("Invalid byte number"))?,
                        )?
                        .handle)
                    },
                )?;

                update_stream_maps(skel, u32::from(stream_handle), &xdp_flow)
            })
            .context("Failed to configure flow")
    }

    fn setup_reverse_flow(
        &mut self,
        flow_config: &Flow,
        _interface_config: &PhysicalInterface,
    ) -> Result<()> {
        let xdp_flow = XdpFlowBuilder::new()
            .outgoing_interface(
                (self.nametoindex)(flow_config.app()?.ingress_interface()?)?.try_into()?,
            )
            .build();
        let stream_identification = StreamIdentificationBuilder::new()
            // use source instead destination since this is the reverse path!
            .destination_address(*flow_config.next_hop()?.source()?)
            .vid(*flow_config.next_hop()?.vid()?)
            .build();

        self.skels
            .with_interface(flow_config.next_hop()?.outgoing_interface()?, |skel| {
                let stream_handle = find_or_add_stream(
                    skel.maps().streams(),
                    skel.maps().num_streams(),
                    &stream_identification,
                    |s| {
                        Ok(XdpFlow::from_bytes(
                            s.try_into().map_err(|_e| anyhow!("Invalid byte number"))?,
                        )?
                        .handle)
                    },
                )?;

                update_stream_maps(skel, u32::from(stream_handle), &xdp_flow)
            })
            .context("Failed to configure reverse flow")
    }
}

impl BpfDataPlane<'_> {
    /// Create a new `BpfDataPlane`
    pub fn new(debug_output: bool) -> Self {
        //let nametoindex: NameToIndexCallback = Box::new(|interface| Ok(i32::try_from(nix::net::if_::if_nametoindex(interface)?)?));

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
    xdp_flow: &XdpFlow,
) -> Result<()> {
    let xdp_flow_bytes = xdp_flow.to_bytes();

    skel.maps_mut().streams().update(
        &stream_handle.to_ne_bytes(),
        &xdp_flow_bytes,
        MapFlags::ANY,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::StreamIdentification;
    use crate::configuration::{
        AppFlowBuilder, FillDefaults, FlowBuilder, PhysicalInterfaceBuilder,
        StreamIdentificationBuilder, TsnNextHopBuilder,
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

    const INGRESS_INTERFACE: &str = "eth1";
    const OUTGOING_INTERFACE: &str = "eth12";
    const PRIORITY: u8 = 6;
    const SOURCE: MacAddress = MacAddress::new([0xEE, 0xcb, 0xcb, 0xcb, 0xcb, 0xcb]);
    const DESTINATION: MacAddress = MacAddress::new([0xab, 0xcb, 0xcb, 0xcb, 0xcb, 0xcb]);
    const VID: u16 = 2;

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
        progs.expect_on_mapped_cpu().returning(generate_program);
        progs.expect_backpath().returning(generate_program);
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

        maps_mut.expect_stream_handles().returning(|| {
            let mut map = Map::default();
            map.expect_update().times(1).returning(|key, value, _| {
                let stream_id_bytes = generate_stream_identification(3).to_bytes().unwrap();
                assert_eq!(key, stream_id_bytes);
                assert_eq!(value, vec![1, 0]);
                Ok(())
            });
            map
        });

        maps_mut.expect_cpu_map().returning(|| {
            let mut map = Map::default();
            map.expect_update()
                .times(1)
                .returning(|_key, _value, _| Ok(()));
            map
        });

        maps_mut.expect_flows_back().returning(|| {
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

        maps.expect_stream_handles().returning(|| {
            let mut map = Map::default();
            map.expect_lookup().times(1).returning(|key, _flags| {
                if key == generate_stream_identification(3).to_bytes().unwrap() {
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
            map.expect_lookup().returning(|_key, _flags| {
                Ok(Some(XdpFlowBuilder::new().build().to_bytes().into()))
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

        let flow_config = FlowBuilder::new()
            .app(
                AppFlowBuilder::new()
                    .stream(generate_stream_identification(3))
                    .ingress_interface(INGRESS_INTERFACE.to_owned())
                    .build(),
            )
            .next_hop(
                TsnNextHopBuilder::new()
                    .priority(PRIORITY)
                    .outgoing_interface(OUTGOING_INTERFACE.to_owned())
                    .source(SOURCE)
                    .destination(DESTINATION)
                    .vid(VID)
                    .build(),
            )
            .build();
        let mut interface_config = PhysicalInterfaceBuilder::new().build();
        interface_config.fill_defaults()?;

        data_plane.setup_flow(&flow_config, &interface_config)?;
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

        let flow_config = FlowBuilder::new()
            .app(
                AppFlowBuilder::new()
                    .stream(generate_stream_identification(3))
                    .ingress_interface(INGRESS_INTERFACE.to_owned())
                    .build(),
            )
            .next_hop(
                TsnNextHopBuilder::new()
                    .priority(PRIORITY)
                    .outgoing_interface(OUTGOING_INTERFACE.to_owned())
                    .source(SOURCE)
                    .destination(DESTINATION)
                    .vid(VID)
                    .build(),
            )
            .build();
        let mut interface_config = PhysicalInterfaceBuilder::new().build();
        interface_config.fill_defaults().unwrap();

        data_plane
            .setup_flow(&flow_config, &interface_config)
            .unwrap();
    }
}
