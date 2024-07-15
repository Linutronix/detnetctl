// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::configuration::{OutgoingL2, Stream, StreamIdentification};
use anyhow::{anyhow, Context, Result};
use etherparse::{EtherType, Ethernet2Header, SingleVlanHeader, VlanId, VlanPcp};
use eui48::MacAddress;
use flagset::{flags, FlagSet};
use libbpf_rs::libbpf_sys;
use libbpf_rs::ErrorKind;
use libbpf_rs::{MapFlags, MapType, XdpFlags};
use std::cmp::max;
use std::collections::BTreeMap;
use std::fs::remove_file;
use std::mem::size_of;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

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
    libbpf_rs::{Map, MapHandle, Xdp},
    std::os::fd::AsFd,
};

#[cfg(not(test))]
#[allow(
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction,
    unreachable_pub
)] // this is generated code
mod postprocessing_bpf {
    include!(concat!(env!("OUT_DIR"), "/postprocessing.skel.rs"));
}
#[cfg(not(test))]
use {
    postprocessing_bpf::postprocessing_rodata_types::vlan_ethhdr,
    postprocessing_bpf::OpenPostprocessingSkel, postprocessing_bpf::PostprocessingSkelBuilder,
};

#[cfg(test)]
use crate::bpf::mocks as core_mocks;
#[cfg(test)]
mod mocks;
#[cfg(test)]
use {
    core_mocks::MockMap as Map, core_mocks::MockXdp as Xdp,
    mocks::postprocessing_rodata_types::vlan_ethhdr, mocks::MockDataPlaneSkel as DataPlaneSkel,
    mocks::MockDataPlaneSkelBuilder as DataPlaneSkelBuilder, mocks::MockMapHandle as MapHandle,
    mocks::MockOpenPostprocessingSkel as OpenPostprocessingSkel,
    mocks::MockPostprocessingSkelBuilder as PostprocessingSkelBuilder,
};

use crate::bpf::{find_or_add_stream, Attacher, SkelManager};
use crate::data_plane::DataPlane;

const MAX_REPLICATIONS: u32 = 6;
const CPUMAP_QUEUE_SIZE: u32 = 4096;

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
    fn to_bytes(&self) -> [u8; 3] {
        let mut result: [u8; 3] = [0; 3];
        result[0..2].copy_from_slice(&self.handle.to_ne_bytes()[..]); // 2 bytes
        result[2] = self.flags.bits(); // 1 byte
        result
    }

    fn from_bytes(bytes: [u8; 3]) -> Result<Self> {
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

#[derive(Debug)]
struct VlanEthernetHeader {
    vlan_header: SingleVlanHeader,
    ethernet_header: Ethernet2Header,
}

impl VlanEthernetHeader {
    fn to_vlan_ethhdr(&self) -> Result<vlan_ethhdr> {
        let mut hdr = vlan_ethhdr::default();
        hdr.__anon_1.addrs.h_dest = self.ethernet_header.destination;
        hdr.__anon_1.addrs.h_source = self.ethernet_header.source;
        hdr.h_vlan_proto = self.ethernet_header.ether_type.into();
        hdr.h_vlan_TCI = u16::from_ne_bytes(
            self.vlan_header.to_bytes()[0..2]
                .try_into()
                .map_err(|_e| anyhow!("Invalid byte number"))?,
        );
        hdr.h_vlan_encapsulated_proto = self.vlan_header.ether_type.into();
        Ok(hdr)
    }
}

struct VlanEthernetHeaderBuilder {
    hdr: VlanEthernetHeader,
}

impl VlanEthernetHeaderBuilder {
    fn new() -> Self {
        Self {
            hdr: VlanEthernetHeader {
                vlan_header: SingleVlanHeader::default(),
                ethernet_header: Ethernet2Header::default(),
            },
        }
    }

    fn source(mut self, source: MacAddress) -> Self {
        self.hdr.ethernet_header.source = source.to_array();
        self
    }

    fn destination(mut self, destination: MacAddress) -> Self {
        self.hdr.ethernet_header.destination = destination.to_array();
        self
    }

    fn vlan_tci(mut self, vlan: u16, pcp: u8) -> Result<Self> {
        self.hdr.vlan_header.pcp = VlanPcp::try_new(pcp)?;
        self.hdr.vlan_header.drop_eligible_indicator = false;
        self.hdr.vlan_header.vlan_id = VlanId::try_new(vlan)?;
        self.hdr.ethernet_header.ether_type = EtherType::VLAN_TAGGED_FRAME;
        Ok(self)
    }

    const fn ether_type(mut self, ether_type: EtherType) -> Self {
        self.hdr.vlan_header.ether_type = ether_type;
        self
    }

    const fn build(self) -> VlanEthernetHeader {
        self.hdr
    }
}

struct BpfDevmapVal {
    ifindex: u32,
    bpf_prog: RawFd,
}

impl BpfDevmapVal {
    fn to_bytes(&self) -> [u8; 8] {
        let mut result: [u8; 8] = [0; 8];
        result[0..4].copy_from_slice(&self.ifindex.to_ne_bytes()[..]); // 4 bytes
        result[4..8].copy_from_slice(&self.bpf_prog.to_ne_bytes()[..]); // 4 bytes
        result
    }
}

struct BpfCpumapVal {
    qsize: u32,
    bpf_prog: RawFd,
}

impl BpfCpumapVal {
    fn to_bytes(&self) -> [u8; 8] {
        let mut result: [u8; 8] = [0; 8];
        result[0..4].copy_from_slice(&self.qsize.to_ne_bytes()[..]); // 4 bytes
        result[4..8].copy_from_slice(&self.bpf_prog.to_ne_bytes()[..]); // 4 bytes
        result
    }
}

type GenerateSkelCallback = Box<dyn FnMut() -> DataPlaneSkelBuilder + Send>;
type GenerateSkelPostprocessingCallback = Box<dyn FnMut() -> PostprocessingSkelBuilder + Send>;
type NameToIndexCallback = Box<dyn FnMut(&str) -> Result<i32> + Send>;
type CreateDevmapCallback = Box<dyn FnMut() -> Result<MapHandle> + Send>;

/// Installs eBPFs for packet handling
pub struct BpfDataPlane<'a> {
    skels: SkelManager<DataPlaneSkel<'a>>,
    nametoindex: NameToIndexCallback,
    generate_skel: GenerateSkelCallback,
    create_devmap: CreateDevmapCallback,
    generate_skel_postprocessing: GenerateSkelPostprocessingCallback,
}

struct DataPlaneAttacher {
    generate_skel: GenerateSkelCallback,
    nametoindex: NameToIndexCallback,
    debug_output: bool,
}

impl DataPlane for BpfDataPlane<'_> {
    fn setup_stream(
        &mut self,
        stream_config: &Stream,
        queues: &BTreeMap<(String, u8), u16>,
    ) -> Result<()> {
        let interfaces = stream_config
            .incoming_interfaces()?
            .iter()
            .map(String::as_str)
            .collect::<Vec<&str>>();

        for stream_identification in stream_config.identifications()? {
            self.skels
                .with_interfaces(&interfaces, |skel| {
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

                    let outgoing_l2 = stream_config.outgoing_l2()?;

                    let xdp_stream = XdpStreamBuilder::new()
                        .handle(stream_handle)
                        .sequence_generation(outgoing_l2.len() > 1)
                        .build();

                    update_stream_maps(
                        skel,
                        stream_handle,
                        stream_identification,
                        &xdp_stream,
                        outgoing_l2,
                        queues,
                        &mut UpdateStreamCallbacks {
                            nametoindex: &mut self.nametoindex,
                            create_devmap: &mut self.create_devmap,
                            generate_skel_postprocessing: &mut self.generate_skel_postprocessing,
                        },
                    )
                    .context("Failed to update stream maps")
                })
                .context("Failed to configure stream")?;
        }

        // Install blank XDP program on outgoing_interface.
        // Otherwise, redirected packets will not be sent out.
        // (see https://lore.kernel.org/xdp-newbies/87v86tg5qp.fsf@toke.dk/ )
        // If streams are configured in the other direction as well
        // (with this `outgoing_interface` as `incoming_interface`)
        // it will be reused and filled with proper stream configurations.
        for outgoing_l2 in stream_config.outgoing_l2()? {
            let outgoing_interface = outgoing_l2.outgoing_interface()?;
            if !self.skels.xdp_already_attached(outgoing_interface) {
                self.skels
                    .with_interfaces(&[outgoing_interface], |_skel| Ok(()))
                    .with_context(|| {
                        format!("Failed to configure blank XDP on {outgoing_interface}")
                    })?;
            }
        }

        Ok(())
    }

    fn load_xdp_pass(&mut self, interface: &str) -> Result<()> {
        let ifidx = (self.nametoindex)(interface)?;
        let skel_builder = (self.generate_skel)();

        let open_skel = skel_builder.open()?;
        let skel = open_skel.load()?;
        let progs = skel.progs();

        let xdp = Xdp::new(progs.pass().as_fd());
        xdp.attach(ifidx, XdpFlags::NONE)?;

        Ok(())
    }

    fn pin_xdp_pass(&mut self, path: &Path) -> Result<()> {
        // since program pins are just another reference,
        // removing the pin won't deattach any existing programs
        if path.exists() {
            remove_file(path)?;
        }

        let skel_builder = (self.generate_skel)();

        let open_skel = skel_builder.open()?;
        let mut skel = open_skel.load()?;
        let mut progs = skel.progs_mut();

        progs.pass().pin(path)?;

        Ok(())
    }
}

impl BpfDataPlane<'_> {
    /// Create a new `BpfDataPlane`
    pub fn new(debug_output: bool) -> Self {
        Self {
            nametoindex: Box::new(nametoindex),
            generate_skel: Box::new(DataPlaneSkelBuilder::default),
            skels: SkelManager::new(Box::new(DataPlaneAttacher {
                generate_skel: Box::new(DataPlaneSkelBuilder::default),
                nametoindex: Box::new(nametoindex),
                debug_output,
            })),
            create_devmap: Box::new(create_devmap),
            generate_skel_postprocessing: Box::new(PostprocessingSkelBuilder::default),
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
    fn attach_interfaces(&mut self, interfaces: &[&str]) -> Result<DataPlaneSkel<'a>> {
        let skel_builder = (self.generate_skel)();
        let mut open_skel = skel_builder.open()?;
        open_skel.rodata_mut().debug_output = self.debug_output;

        let mut skel = open_skel.load()?;

        let progs = skel.progs();

        let xdp = Xdp::new(progs.xdp_bridge().as_fd());

        for interface in interfaces {
            let ifidx = (self.nametoindex)(interface)?;
            xdp.attach(ifidx, XdpFlags::NONE)?;
        }

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

struct UpdateStreamCallbacks<'a> {
    nametoindex: &'a mut NameToIndexCallback,
    create_devmap: &'a mut CreateDevmapCallback,
    generate_skel_postprocessing: &'a mut GenerateSkelPostprocessingCallback,
}

fn update_stream_maps(
    skel: &mut DataPlaneSkel<'_>,
    stream_handle: u16,
    stream_identification: &StreamIdentification,
    xdp_stream: &XdpStream,
    outgoing_l2: &[OutgoingL2],
    queues: &BTreeMap<(String, u8), u16>,
    callbacks: &mut UpdateStreamCallbacks<'_>,
) -> Result<()> {
    let redirect_interfaces = (callbacks.create_devmap)()?;

    for (i, l2) in outgoing_l2.iter().enumerate() {
        // Load dedicated postprocessing BPF
        let skel_builder = (callbacks.generate_skel_postprocessing)();
        let mut open_skel = skel_builder.open()?;
        open_skel.rodata_mut().debug_output = skel.rodata().debug_output;

        assemble_target_ethernet_header(&mut open_skel, l2)?;

        // Configure egress CPU for queue mapping
        // For the moment assume a 1:1 mapping from
        // queue to cpu as it is the case for the igc driver
        // as long as at least 4 CPUs are available
        // (see postprocessing.bpf.c for background)
        let mut max_cpu = 0;
        if let Some(cpu) = queues.get(&(l2.outgoing_interface()?.to_owned(), *l2.priority()?)) {
            max_cpu = max(max_cpu, *cpu);
            open_skel.rodata_mut().fixed_egress_cpu = true;
            open_skel.rodata_mut().outgoing_cpu = (*cpu).into();
        }

        let mut postprocessing_skel = open_skel.load()?;

        // Initialize CPUMAP
        for cpu in 0..max_cpu {
            let cpumap_val = BpfCpumapVal {
                qsize: CPUMAP_QUEUE_SIZE,
                bpf_prog: 0,
            };

            postprocessing_skel.maps_mut().cpu_map().update(
                &cpu.to_ne_bytes(),
                &cpumap_val.to_bytes(),
                MapFlags::ANY,
            )?;
        }

        // Update map
        let devmap_val = BpfDevmapVal {
            ifindex: (callbacks.nametoindex)(l2.outgoing_interface()?)?.try_into()?,
            bpf_prog: postprocessing_skel
                .progs()
                .xdp_bridge_postprocessing()
                .as_fd()
                .as_raw_fd(),
        };

        redirect_interfaces.update(
            &u32::try_from(i)?.to_ne_bytes(),
            &devmap_val.to_bytes(),
            MapFlags::ANY,
        )?;
    }

    skel.maps_mut().redirect_map().update(
        &stream_handle.to_ne_bytes(),
        &redirect_interfaces.as_fd().as_raw_fd().to_ne_bytes(),
        MapFlags::ANY,
    )?;

    add_initial_entry(skel.maps_mut().seqgen_map(), stream_handle)?;
    add_initial_entry(skel.maps_mut().seqrcvy_map(), stream_handle)?;

    let xdp_stream_bytes = xdp_stream.to_bytes();

    skel.maps_mut().streams().update(
        &stream_identification.to_bytes()?,
        &xdp_stream_bytes,
        MapFlags::ANY,
    )?;

    Ok(())
}

fn add_initial_entry(map: &Map, stream_handle: u16) -> Result<()> {
    let initial_value = vec![0; map.info()?.info.value_size.try_into()?];
    map.update(
        &stream_handle.to_ne_bytes(),
        &initial_value,
        MapFlags::NO_EXIST, // keep existing state
    )
    .or_else(|err| {
        if err.kind() == ErrorKind::AlreadyExists {
            Ok(()) // ignore existing entry to keep state
        } else {
            Err(err)
        }
    })?;

    Ok(())
}

fn assemble_target_ethernet_header(
    open_skel: &mut OpenPostprocessingSkel<'_>,
    l2: &OutgoingL2,
) -> Result<()> {
    let mut hdr = VlanEthernetHeaderBuilder::new();

    if let Some(source) = l2.source_opt() {
        hdr = hdr.source(*source);
        open_skel.rodata_mut().overwrite_source_addr = true;
    }

    if let Some(destination) = l2.destination_opt() {
        hdr = hdr.destination(*destination);
        open_skel.rodata_mut().overwrite_dest_addr = true;
    }

    if let Some(vid) = l2.vid_opt() {
        let pcp = l2.pcp_opt().unwrap_or(&0);
        hdr = hdr.vlan_tci(*vid, *pcp)?;
        open_skel.rodata_mut().overwrite_vlan_proto_and_tci = true;
    } else if l2.pcp_opt().is_some() {
        return Err(anyhow!(
            "PCP can only be set if VLAN identifier is also provided"
        ));
    }

    if let Some(ethertype) = l2.ether_type_opt() {
        hdr = hdr.ether_type(EtherType(*ethertype));
        open_skel.rodata_mut().overwrite_ether_type = true;
    }

    let hdr = hdr.build();
    open_skel.rodata_mut().target_outer_hdr = hdr.to_vlan_ethhdr()?;

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
    use mocks::MockOpenPostprocessingSkel as OpenPostprocessingSkel;
    use mocks::MockPostprocessingMapsMut as PostprocessingMapsMut;
    use mocks::MockPostprocessingProgs as PostprocessingProgs;
    use mocks::MockPostprocessingSkel as PostprocessingSkel;
    use std::os::fd::BorrowedFd;

    const INCOMING_INTERFACE: &str = "eth1";
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

    fn generate_open_skel<'a>() -> OpenDataPlaneSkel<'a> {
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
        skel.expect_rodata()
            .returning(|| mocks::bpf_rodata_types::rodata {
                debug_output: false,
            });
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

        maps_mut.expect_seqrcvy_map().returning(|| {
            let mut map = Map::default();
            map.expect_update().returning(|_key, _value, _| Ok(()));
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

    fn generate_postprocessing_skel_builder() -> PostprocessingSkelBuilder {
        let mut builder = PostprocessingSkelBuilder::default();
        builder
            .expect_open()
            .times(1)
            .returning(move || Ok(generate_open_postprocessing_skel()));
        builder
    }

    fn generate_open_postprocessing_skel<'a>() -> OpenPostprocessingSkel<'a> {
        let mut open_skel = OpenPostprocessingSkel::default();
        open_skel
            .expect_load()
            .returning(move || Ok(generate_postprocessing_skel()));
        open_skel
            .expect_rodata_mut()
            .returning(|| mocks::postprocessing_rodata_types::rodata {
                debug_output: false,
                overwrite_dest_addr: false,
                overwrite_source_addr: false,
                overwrite_vlan_proto_and_tci: false,
                overwrite_ether_type: false,
                target_outer_hdr: vlan_ethhdr::default(),
                fixed_egress_cpu: false,
                outgoing_cpu: 0,
            });
        open_skel
    }

    fn generate_postprocessing_skel<'a>() -> PostprocessingSkel<'a> {
        let mut skel = PostprocessingSkel::default();
        skel.expect_progs().returning(generate_postprocessing_progs);
        skel.expect_maps_mut()
            .returning(generate_postprocessing_maps_mut);
        skel
    }

    fn generate_postprocessing_progs() -> PostprocessingProgs {
        let mut progs = PostprocessingProgs::default();
        progs
            .expect_xdp_bridge_postprocessing()
            .returning(generate_postprocessing_program);
        progs
    }

    fn generate_postprocessing_maps_mut() -> PostprocessingMapsMut {
        let mut maps_mut = PostprocessingMapsMut::default();
        maps_mut.expect_cpu_map().returning(|| {
            let mut map = Map::default();
            map.expect_update()
                .times(1)
                .returning(|_key, _value, _| Ok(()));
            map
        });
        maps_mut
    }

    fn generate_postprocessing_program() -> Program {
        let mut prog = Program::default();
        // SAFETY: Only for testing
        unsafe {
            prog.expect_as_fd()
                .times(1)
                .return_const(BorrowedFd::borrow_raw(1));
        }
        prog
    }

    #[test]
    fn test_setup_happy() -> Result<()> {
        let mut data_plane = BpfDataPlane {
            nametoindex: Box::new(|_interface| Ok(3)),
            generate_skel: Box::new(generate_skel_builder),
            skels: SkelManager::new(Box::new(DataPlaneAttacher {
                generate_skel: Box::new(generate_skel_builder),
                nametoindex: Box::new(|_interface| Ok(3)),
                debug_output: false,
            })),
            create_devmap: Box::new(|| Ok(create_devmap())),
            generate_skel_postprocessing: Box::new(generate_postprocessing_skel_builder),
        };

        let mut stream_config = StreamBuilder::new()
            .identifications(vec![generate_stream_identification(3)])
            .incoming_interfaces(vec![INCOMING_INTERFACE.to_owned()])
            .outgoing_l2(vec![OutgoingL2Builder::new()
                .outgoing_interface(OUTGOING_INTERFACE.to_owned())
                .source(SOURCE)
                .destination(DESTINATION)
                .vid(VID)
                .priority(PRIORITY)
                .build()])
            .build();

        stream_config.fill_defaults()?;

        data_plane.setup_stream(
            &stream_config,
            &BTreeMap::from([((OUTGOING_INTERFACE.to_owned(), PRIORITY), 3)]),
        )?;
        Ok(())
    }

    #[test]
    #[should_panic(expected = "interface not found")]
    fn test_setup_interface_not_found() {
        let mut data_plane = BpfDataPlane {
            nametoindex: Box::new(|_interface| Err(anyhow!("interface not found"))),
            generate_skel: Box::new(generate_skel_builder),
            skels: SkelManager::new(Box::new(DataPlaneAttacher {
                generate_skel: Box::new(generate_skel_builder),
                nametoindex: Box::new(|_interface| Err(anyhow!("interface not found"))),
                debug_output: false,
            })),
            create_devmap: Box::new(|| Ok(create_devmap())),
            generate_skel_postprocessing: Box::new(generate_postprocessing_skel_builder),
        };

        let mut stream_config = StreamBuilder::new()
            .identifications(vec![generate_stream_identification(3)])
            .incoming_interfaces(vec![INCOMING_INTERFACE.to_owned()])
            .outgoing_l2(vec![OutgoingL2Builder::new()
                .outgoing_interface(OUTGOING_INTERFACE.to_owned())
                .source(SOURCE)
                .destination(DESTINATION)
                .vid(VID)
                .priority(PRIORITY)
                .build()])
            .build();

        stream_config.fill_defaults().unwrap();

        data_plane
            .setup_stream(
                &stream_config,
                &BTreeMap::from([((OUTGOING_INTERFACE.to_owned(), PRIORITY), 3)]),
            )
            .unwrap();
    }
}
