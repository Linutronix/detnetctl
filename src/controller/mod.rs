// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Core component of the node controller
//!
//! The controller is combining the configuration, the NIC setup and the dispatcher
//! to perform a complete protection of an application.
//!
//! ```
//! use detnetctl::configuration::{Configuration, YAMLConfiguration};
//! use detnetctl::controller::{Controller, Setup, Protect};
//! use detnetctl::data_plane::{DummyDataPlane, DataPlane};
//! use detnetctl::dispatcher::{DummyDispatcher, Dispatcher};
//! use detnetctl::interface_setup::DummyInterfaceSetup;
//! use detnetctl::queue_setup::{DummyQueueSetup, QueueSetup};
//!
//! # #[path = "../configuration/doctest.rs"]
//! # mod doctest;
//! # let tmpfile = doctest::generate_example_yaml();
//! # let filepath = tmpfile.path();
//! use futures::lock::Mutex;
//! use std::fs::File;
//! use std::path::PathBuf;
//! use std::sync::Arc;
//!
//! # tokio_test::block_on(async {
//! let controller = Controller::new();
//! let cgroup = PathBuf::from("/sys/fs/cgroup/system.slice/some.service/");
//! let mut configuration = Arc::new(Mutex::new(YAMLConfiguration::new()));
//! configuration.lock().await.read(File::open(filepath)?)?;
//! let mut queue_setup = Arc::new(Mutex::new(DummyQueueSetup));
//! let mut data_plane = Arc::new(Mutex::new(DummyDataPlane));
//! let mut dispatcher = Arc::new(Mutex::new(DummyDispatcher));
//! let mut interface_setup = Arc::new(Mutex::new(DummyInterfaceSetup));
//! controller
//!     .setup(configuration.clone(), queue_setup, data_plane.clone(), dispatcher.clone(), interface_setup)
//!     .await?;
//! controller
//!     .protect("app0", &cgroup, configuration, dispatcher)
//!     .await?;
//! # Ok::<(), anyhow::Error>(())
//! # });
//! # Ok::<(), anyhow::Error>(())
//! ```

use crate::configuration::detnet::Flow;
use crate::configuration::{
    BridgedApp, Configuration, FillDefaults, Interface, OutgoingL2, Stream, StreamIdentification,
    StreamIdentificationBuilder, UnbridgedApp,
};
use crate::data_plane::DataPlane;
use crate::dispatcher::{Dispatcher, Protection};
use crate::interface_setup::{InterfaceSetup, LinkState};
use crate::queue_setup::QueueSetup;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use futures::lock::Mutex;
use options_struct_derive::validate_are_some;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::time::Instant;

const XDP_PASS_PIN_PATH: &str = "/sys/fs/bpf/detnetctl-pass";

/// Defines a setup operation
#[async_trait]
pub trait Setup {
    /// Setup the system considering all application configurations
    async fn setup(
        &self,
        mut configuration: Arc<Mutex<dyn Configuration + Send>>,
        queue_setup: Arc<Mutex<dyn QueueSetup + Send>>,
        mut data_plane: Arc<Mutex<dyn DataPlane + Send>>,
        mut dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
        mut interface_setup: Arc<Mutex<dyn InterfaceSetup + Sync + Send>>,
    ) -> Result<()>;
}

/// Defines a protection operation
#[async_trait]
pub trait Protect {
    /// Protect an application by setting the cgroup for the provided `app_name`
    async fn protect(
        &self,
        app_name: &str,
        cgroup: &Path,
        mut configuration: Arc<Mutex<dyn Configuration + Send>>,
        mut dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
    ) -> Result<()>;
}

/// Struct to perform the protection on
#[derive(Default)]
pub struct Controller;

impl Controller {
    /// Create a new controller
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

struct ExpandedInterface {
    config: Interface,

    /// Unbridged apps that have this physical interface configured
    unbridged_apps: Vec<UnbridgedApp>,

    /// Streams that have this physical interface as `outgoing_l2.outgoing_interface`
    streams_to_protect: Vec<StreamIdentification>,

    /// Network namespace if this is a virtual interface of a bridged app
    network_namespace: Option<String>,
}

struct ExpandedStream {
    stream: Stream,
    queues: BTreeMap<(String, u8), u16>, // egress queues calculated from priority of each outgoing_l2
}

struct ExpandedFlow {
    flow: Flow,
    queues: BTreeMap<(String, u8), u16>, // egress queues calculated from priority of each outgoing_l2
}

struct ExpandedConfiguration {
    interfaces: BTreeMap<String, ExpandedInterface>,
    bridged_apps: BTreeMap<String, BridgedApp>,
    streams: Vec<ExpandedStream>,
    flows: Vec<ExpandedFlow>,
}

async fn fetch_expanded_configuration(
    configuration: Arc<Mutex<dyn Configuration + Send>>,
) -> Result<ExpandedConfiguration> {
    let mut config = configuration.lock().await;

    let mut interfaces = config.get_interfaces()?;
    let mut unbridged_apps = config.get_unbridged_apps()?;
    let mut bridged_apps = config.get_bridged_apps()?;
    let mut streams = config.get_streams()?;
    let mut flows = config.get_flows()?;

    for interface_config in interfaces.values_mut() {
        interface_config.fill_defaults()?;
        if interface_config.schedule_opt().is_some() {
            validate_are_some!(interface_config, schedule, taprio, pcp_encoding)?;
        }
    }

    for app_config in unbridged_apps.values_mut() {
        app_config.fill_defaults()?;
        validate_are_some!(
            app_config,
            physical_interface,
            bind_interface,
            stream,
            priority
        )?;
    }

    for app_config in bridged_apps.values_mut() {
        app_config.fill_defaults()?;
        validate_are_some!(
            app_config,
            virtual_interface_app,
            netns_app,
            virtual_interface_bridge,
        )?;
    }

    for stream in streams.values_mut() {
        stream.fill_defaults()?;
        validate_are_some!(stream, incoming_interfaces, identifications, outgoing_l2)?;
    }

    for (flow_name, flow) in &mut flows {
        flow.fill_defaults()?;

        if flow.incoming_app_flows_is_some() && !flow.outgoing_forwarding_is_some() {
            return Err(anyhow!(
                "{flow_name}: Incoming app flows, but no outgoing forwarding"
            ));
        }

        if flow.incoming_forwarding_is_some() && !flow.outgoing_app_flows_is_some() {
            return Err(anyhow!(
                "{flow_name}: Incoming forwarding, but no outgoing app flows"
            ));
        }
    }

    println!("Fetched from configuration module:");
    println!("Interfaces: {interfaces:#?}");
    println!("Unbridged Apps: {unbridged_apps:#?}");
    println!("Bridged Apps: {bridged_apps:#?}");
    println!("TSN Streams: {streams:#?}");
    println!("DetNet Flows: {flows:#?}");

    Ok(ExpandedConfiguration {
        interfaces: collect_expanded_interfaces(
            &interfaces,
            &unbridged_apps,
            &bridged_apps,
            &streams,
            &flows,
        )?,
        bridged_apps,
        streams: collect_expanded_streams(&streams, &interfaces)?,
        flows: collect_expanded_flows(&flows, &interfaces)?,
    })
}

fn collect_expanded_interfaces(
    interfaces: &BTreeMap<String, Interface>,
    unbridged_apps: &BTreeMap<String, UnbridgedApp>,
    bridged_apps: &BTreeMap<String, BridgedApp>,
    streams: &BTreeMap<String, Stream>,
    flows: &BTreeMap<String, Flow>,
) -> Result<BTreeMap<String, ExpandedInterface>> {
    interfaces
        .iter()
        .map(|(name, ifconfig)| -> Result<(String, ExpandedInterface)> {
            // find all matching streams to protect from coming via TC
            let mut streams_to_protect = vec![];
            for stream in streams.values() {
                for outgoing_l2 in stream.outgoing_l2()? {
                    if outgoing_l2.outgoing_interface()? == name {
                        for id in stream.identifications()? {
                            let mut stream_id =
                                StreamIdentificationBuilder::from_struct(id.clone());

                            if let Some(destination) = outgoing_l2.destination_opt() {
                                stream_id = stream_id.destination_address(*destination);
                            }

                            if let Some(vid) = outgoing_l2.vid_opt() {
                                stream_id = stream_id.vid(*vid);
                            }

                            streams_to_protect.push(stream_id.build());
                        }
                    }
                }
            }

            // also add the encapsulated flows as streams to protect
            for flow in flows.values() {
                let Some(outgoings) = flow.outgoing_forwarding_opt() else {
                    continue;
                };

                for outgoing in outgoings {
                    for outgoing_l2 in outgoing.outgoing_l2()? {
                        if outgoing_l2.outgoing_interface()? == name {
                            let stream_id = StreamIdentificationBuilder::new()
                                .destination_address(
                                    *outgoing_l2
                                        .destination()
                                        .context("Destination needed for DetNet over L2")?,
                                )
                                .vid(
                                    *outgoing_l2
                                        .vid()
                                        .context("VLAN ID needed for DetNet over L2")?,
                                );

                            streams_to_protect.push(stream_id.build());
                        }
                    }
                }
            }

            // find matching bridged app to set the network namespace
            let mut network_namespace = None;
            for app_config in bridged_apps.values() {
                let veth_app = app_config.virtual_interface_app()?;
                let netns_app = app_config.netns_app()?;

                if veth_app == name {
                    network_namespace = Some(netns_app.to_owned());
                    break;
                }

                for vid in app_config.vlans_opt().unwrap_or(&vec![]) {
                    if &format!("{veth_app}.{vid}") == name {
                        network_namespace = Some(netns_app.to_owned());
                        break;
                    }
                }
            }

            Ok((
                name.clone(),
                ExpandedInterface {
                    config: ifconfig.clone(),
                    streams_to_protect,

                    // find all matching unbridged apps
                    unbridged_apps: unbridged_apps
                        .values()
                        .map(|app_config| {
                            Ok((app_config.physical_interface()? == name)
                                .then_some(app_config.clone()))
                        })
                        .filter_map(Result::transpose)
                        .collect::<Result<Vec<UnbridgedApp>>>()?,

                    network_namespace,
                },
            ))
        })
        .collect()
}

fn queue_from_outgoing_l2(
    outgoing_l2: &OutgoingL2,
    interfaces: &BTreeMap<String, Interface>,
) -> Result<Option<((String, u8), u16)>> {
    let interface_name = outgoing_l2.outgoing_interface()?;
    let Some(interface) = interfaces.get(interface_name) else {
        return Ok(None);
    };

    let Some(priority) = outgoing_l2.priority_opt() else {
        return Ok(None);
    };

    let Some(prio_to_tc) = interface.schedule_opt().and_then(|s| s.priority_map_opt()) else {
        return Ok(None);
    };

    let Some(tc_to_queue) = interface.taprio_opt().and_then(|t| t.queues_opt()) else {
        return Ok(None);
    };

    let tc = prio_to_tc
        .get(priority)
        .ok_or_else(|| anyhow!("Priority not found in priority_map"))?;
    let queue_mapping = tc_to_queue
        .get(usize::from(*tc))
        .ok_or_else(|| anyhow!("TC not found in queue mapping"))?;

    // select just the first queue for this tc for now
    let queue = queue_mapping.offset;

    Ok(Some(((interface_name.clone(), *priority), queue)))
}

fn collect_expanded_streams(
    streams: &BTreeMap<String, Stream>,
    interfaces: &BTreeMap<String, Interface>,
) -> Result<Vec<ExpandedStream>> {
    streams
        .values()
        .map(|stream| -> Result<ExpandedStream> {
            Ok(ExpandedStream {
                stream: stream.clone(),
                queues: stream
                    .outgoing_l2()?
                    .iter()
                    .map(|outgoing_l2| queue_from_outgoing_l2(outgoing_l2, interfaces))
                    .filter_map(Result::transpose)
                    .collect::<Result<BTreeMap<(String, u8), u16>>>()?,
            })
        })
        .collect()
}

fn collect_expanded_flows(
    flows: &BTreeMap<String, Flow>,
    interfaces: &BTreeMap<String, Interface>,
) -> Result<Vec<ExpandedFlow>> {
    flows
        .values()
        .map(|flow| -> Result<ExpandedFlow> {
            let mut queues = BTreeMap::new();

            if let Some(ofs) = flow.outgoing_forwarding_opt() {
                for of in ofs {
                    for outgoing_l2 in of.outgoing_l2()? {
                        if let Some(kv) = queue_from_outgoing_l2(outgoing_l2, interfaces)? {
                            queues.insert(kv.0, kv.1);
                        }
                    }
                }
            }

            Ok(ExpandedFlow {
                flow: flow.clone(),
                queues,
            })
        })
        .collect()
}

#[async_trait]
impl Setup for Controller {
    async fn setup(
        &self,
        configuration: Arc<Mutex<dyn Configuration + Send>>,
        queue_setup: Arc<Mutex<dyn QueueSetup + Send>>,
        data_plane: Arc<Mutex<dyn DataPlane + Send>>,
        dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
        interface_setup: Arc<Mutex<dyn InterfaceSetup + Sync + Send>>,
    ) -> Result<()> {
        let start = Instant::now();
        println!("Setup of DetNet system");

        // Fetch configurations for interfaces and apps
        let config = fetch_expanded_configuration(configuration.clone())
            .await
            .context("Fetching the configuration failed")?;

        // Setup all veth pairs for the bridged applications
        for (name, app_config) in &config.bridged_apps {
            let virtual_interface_app = app_config.virtual_interface_app()?;

            let locked_interface_setup = interface_setup.lock().await;
            locked_interface_setup
                .setup_veth_pair_with_vlans(
                    virtual_interface_app,
                    app_config.netns_app()?,
                    app_config.virtual_interface_bridge()?,
                    app_config.vlans_opt().unwrap_or(&vec![]),
                )
                .await
                .with_context(|| format!("Setting up veth pair for {name} failed"))?;

            // Load dummy XDP for app side of veth
            // pair, otherwise traffic redirected
            // via XDP is not handled
            let mut locked_data_plane = data_plane.lock().await;
            let xdp_pin_path = Path::new(XDP_PASS_PIN_PATH);
            locked_data_plane
                .pin_xdp_pass(xdp_pin_path)
                .context("Pinning dummy XDP failed")?;

            let netns = Some(app_config.netns_app()?.to_owned());

            locked_interface_setup
                .attach_pinned_xdp(virtual_interface_app, &netns, xdp_pin_path)
                .await?;

            // Disable VLAN offload for all outgoing traffic
            // on app side of veth so XDP can properly process the VLAN tags
            locked_interface_setup
                .set_vlan_offload(virtual_interface_app, Some(false), Some(false), &netns)
                .await
                .with_context(|| {
                    format!("Disabling VLAN offload for {virtual_interface_app} failed")
                })?;
        }

        // Install all XDPs for the streams and flows
        install_xdps(&config, &data_plane, &interface_setup).await?;

        // Configure IP and MAC addresses and promiscuous mode
        perform_interface_setup(&config, &interface_setup).await?;

        // Set both sides of the veth pairs up
        set_veths_up(&config, &interface_setup).await?;

        // Iterate over all interfaces with schedule configuration
        // By this approach, instead of iterating over the apps,
        // we need to setup each interface only once.
        for (name, interface) in &config.interfaces {
            let locked_interface_setup = interface_setup.lock().await;

            let setup_result = setup_before_interface_up(
                name,
                interface,
                queue_setup.clone(),
                dispatcher.clone(),
                &*locked_interface_setup,
            )
            .await; // No ? since we need to ensure that the link is up again even after error

            let if_up_result = set_interface_state(
                name,
                LinkState::Up,
                &interface.network_namespace,
                &*locked_interface_setup,
            )
            .await;

            // The first occurred error shall be returned, but a potential second still be printed
            if let Err(if_up_error) = if_up_result {
                return match setup_result {
                    Ok(()) => Err(if_up_error),
                    Err(setup_error) => {
                        eprintln!("After setup failed, interface up failed, too: {if_up_error}");
                        Err(setup_error)
                    }
                };
            }

            setup_result?;

            // Set logical interfaces up
            for app_config in &interface.unbridged_apps {
                set_interface_state(
                    app_config.bind_interface()?,
                    LinkState::Up,
                    &None,
                    &*locked_interface_setup,
                )
                .await?;
            }
        }

        println!("  Finished after {:.1?}", start.elapsed());

        Ok(())
    }
}

async fn install_xdps(
    config: &ExpandedConfiguration,
    data_plane: &Arc<Mutex<dyn DataPlane + Send>>,
    interface_setup: &Arc<Mutex<dyn InterfaceSetup + Sync + Send>>,
) -> Result<()> {
    let mut locked_data_plane = data_plane.lock().await;
    let locked_interface_setup = interface_setup.lock().await;

    for stream in &config.streams {
        locked_data_plane
            .setup_stream(&stream.stream, &stream.queues)
            .context("Installing stream via XDP failed")?;

        // Disable VLAN offload for all incoming traffic
        // so XDP can properly process the VLAN tags
        for interface in stream.stream.incoming_interfaces()? {
            locked_interface_setup
                .set_vlan_offload(interface, Some(false), Some(false), &None)
                .await
                .context("Disabling VLAN offload failed")?;
        }
    }

    for flow in &config.flows {
        locked_data_plane
            .setup_flow(&flow.flow, &flow.queues)
            .context("Installing flow via XDP failed")?;

        // Disable VLAN offload for all incoming traffic
        // so XDP can properly process the VLAN tags
        if let Some(incoming_flows) = flow.flow.incoming_app_flows_opt() {
            for app_flow in incoming_flows {
                for interface in app_flow.ingress_interfaces()? {
                    locked_interface_setup
                        .set_vlan_offload(interface, Some(false), Some(false), &None)
                        .await
                        .context("Disabling VLAN offload failed")?;
                }
            }
        }
    }

    Ok(())
}

async fn perform_interface_setup(
    config: &ExpandedConfiguration,
    interface_setup: &Arc<Mutex<dyn InterfaceSetup + Sync + Send>>,
) -> Result<()> {
    let locked_interface_setup = interface_setup.lock().await;
    for (name, interface) in &config.interfaces {
        if let Some(address) = interface.config.mac_address_opt() {
            locked_interface_setup
                .set_mac_address(*address, name, &interface.network_namespace)
                .await
                .context("Setting MAC address of interface failed")?;
            println!("  Set {address} to {name}");
        }

        if let Some(addresses) = &interface.config.ip_addresses_opt() {
            for (ip, prefix_length) in *addresses {
                locked_interface_setup
                    .add_ip_address(*ip, *prefix_length, name, &interface.network_namespace)
                    .await
                    .context("Adding IP address to interface failed")?;
                println!("  Added {ip}/{prefix_length} to {name}");
            }
        }

        if let Some(promiscuous) = interface.config.promiscuous_opt() {
            locked_interface_setup
                .set_promiscuous(name, *promiscuous, &interface.network_namespace)
                .await
                .with_context(|| format!("Setting interface {name} to promiscious mode failed"))?;
        }
    }

    Ok(())
}

async fn set_veths_up(
    config: &ExpandedConfiguration,
    interface_setup: &Arc<Mutex<dyn InterfaceSetup + Sync + Send>>,
) -> Result<()> {
    let locked_interface_setup = interface_setup.lock().await;

    for app_config in config.bridged_apps.values() {
        let veth_app = app_config.virtual_interface_app()?;

        set_interface_state(
            app_config.virtual_interface_bridge()?,
            LinkState::Up,
            &None,
            &*locked_interface_setup,
        )
        .await?;

        let netns = Some(app_config.netns_app()?.clone());

        set_interface_state(veth_app, LinkState::Up, &netns, &*locked_interface_setup).await?;

        for vid in app_config.vlans_opt().unwrap_or(&vec![]) {
            let vlan_interface = &format!("{veth_app}.{vid}");
            set_interface_state(
                vlan_interface,
                LinkState::Up,
                &netns,
                &*locked_interface_setup,
            )
            .await?;
        }
    }

    Ok(())
}

#[async_trait]
impl Protect for Controller {
    async fn protect(
        &self,
        app_name: &str,
        cgroup: &Path,
        configuration: Arc<Mutex<dyn Configuration + Send>>,
        dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
    ) -> Result<()> {
        println!("Request to protect {app_name}");

        // Fetch configuration for app
        let app_config = configuration
            .lock()
            .await
            .get_unbridged_app(app_name)
            .context("Fetching the configuration failed")?
            .ok_or_else(|| anyhow!("No configuration found for {app_name}"))?;
        println!("  Fetched from configuration module: {app_config:#?}");

        let stream_id = app_config.stream()?;

        let physical_interface = app_config.physical_interface()?;

        let mut locked_dispatcher = dispatcher.lock().await;
        locked_dispatcher
            .protect_stream(
                physical_interface,
                stream_id,
                Protection {
                    cgroup: Some(cgroup.into()),
                    drop_all: false,
                    drop_without_sk: false,
                },
            )
            .context("Installing protection via the dispatcher failed")?;
        println!("  Protection installed for stream {stream_id:#?} on {physical_interface}");

        Ok(())
    }
}

async fn setup_before_interface_up(
    interface_name: &str,
    interface: &ExpandedInterface,
    queue_setup: Arc<Mutex<dyn QueueSetup + Send>>,
    dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
    interface_setup: &(dyn InterfaceSetup + Sync + Send),
) -> Result<()> {
    set_interface_state(
        interface_name,
        LinkState::Down,
        &interface.network_namespace,
        interface_setup,
    )
    .await?;

    // Setup Queue
    if interface.config.schedule_is_some() {
        queue_setup
            .lock()
            .await
            .apply_config(interface_name, &interface.config)
            .await
            .with_context(|| format!("Setting up the queue for {interface_name} failed"))?;
        println!("  Queues for {interface_name} set up");
    }

    for app_config in &interface.unbridged_apps {
        let bind_interface = app_config.bind_interface()?;
        let stream_id = app_config.stream()?;
        let priority = app_config.priority()?;

        // Setup BPF Hooks
        // It is important to use the physical interface (eth0) and not the logical interface (eth0.2)
        // here, because otherwise it would be possible to use a different logical interface,
        // but same SO_PRIORITY and physical interface. Even though it would not be routed to the
        // same VLAN it could still block the time slot!
        let mut locked_dispatcher = dispatcher.lock().await;
        locked_dispatcher
            .configure_stream(
                interface_name,
                stream_id,
                Some((*priority).into()),
                Some(
                    *interface
                        .config
                        .pcp_encoding()?
                        .pcp_from_priority(*priority)?,
                ),
                Protection {
                    cgroup: app_config
                        .cgroup_opt()
                        .map(|c| <PathBuf as AsRef<Path>>::as_ref(c).into()),
                    drop_all: false,
                    drop_without_sk: false,
                },
            )
            .with_context(|| {
                anyhow!("Installing protection on {interface_name} via the dispatcher failed")
            })?;
        println!(
            "  Dispatcher installed for stream {stream_id:#?} with priority {priority} on {interface_name}"
        );

        if let Some(cgroup) = &app_config.cgroup_opt() {
            println!("  with protection for cgroup {cgroup:?}");
        }

        // Setup bind interface
        if let Some(vid) = stream_id.vid_opt() {
            interface_setup
                .setup_vlan_interface(interface_name, bind_interface, *vid)
                .await
                .context("Setting up VLAN interface failed")?;
            println!("  VLAN interface {bind_interface} properly configured");
        }
    }

    // Protect all configured streams and encapsulated flows from coming via TC, they shall only come via XDP
    for stream_id in &interface.streams_to_protect {
        let mut locked_dispatcher = dispatcher.lock().await;
        locked_dispatcher
            .configure_stream(
                interface_name,
                stream_id,
                None,
                None,
                Protection {
                    cgroup: None,
                    drop_all: true,
                    drop_without_sk: false,
                },
            )
            .with_context(|| anyhow!("Installing protection on TC for XDP streams on {interface_name} via the dispatcher failed"))?;
    }

    Ok(())
}

async fn set_interface_state(
    interface: &str,
    state: LinkState,
    netns: &Option<String>,
    interface_setup: &(dyn InterfaceSetup + Sync + Send),
) -> Result<()> {
    interface_setup
        .set_link_state(state, interface, netns)
        .await
        .with_context(|| format!("Setting interface {interface} {state} failed"))?;
    println!("  Interface {interface} {state}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::detnet::{
        AppFlowBuilder, FlowBuilder, MplsHeaderBuilder, OutgoingForwardingBuilder,
        UdpIpHeaderBuilder,
    };
    use crate::configuration::{
        BridgedAppBuilder, GateControlEntryBuilder, GateOperation, InterfaceBuilder,
        MockConfiguration, Mode, OutgoingL2Builder, QueueMapping, ScheduleBuilder, Stream,
        StreamBuilder, StreamIdentificationBuilder, TaprioConfigBuilder, UnbridgedAppBuilder,
    };
    use crate::data_plane::MockDataPlane;
    use crate::dispatcher::MockDispatcher;
    use crate::interface_setup::MockInterfaceSetup;
    use crate::queue_setup::MockQueueSetup;
    use anyhow::anyhow;
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    fn generate_interface_config() -> Interface {
        InterfaceBuilder::new()
            .schedule(
                ScheduleBuilder::new()
                    .basetime_ns(10)
                    .control_list(vec![GateControlEntryBuilder::new()
                        .operation(GateOperation::SetGates)
                        .time_interval_ns(1000)
                        .traffic_classes(vec![1, 2])
                        .build()])
                    .number_of_traffic_classes(3)
                    .priority_map(BTreeMap::from([(0, 1)]))
                    .build(),
            )
            .taprio(
                TaprioConfigBuilder::new()
                    .mode(Mode::FullOffload)
                    .queues(vec![
                        QueueMapping {
                            count: 2,
                            offset: 0,
                        },
                        QueueMapping {
                            count: 1,
                            offset: 2,
                        },
                        QueueMapping {
                            count: 1,
                            offset: 3,
                        },
                    ])
                    .build(),
            )
            .ip_addresses(vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 3)), 16)])
            .build()
    }

    fn generate_unbridged_app_config(interface: String, vid: u16) -> UnbridgedApp {
        let app_config = UnbridgedAppBuilder::new()
            .bind_interface(format!("{interface}.{vid}"))
            .physical_interface(interface)
            .stream(
                StreamIdentificationBuilder::new()
                    .destination_address("8b:de:82:a1:59:5a".parse().unwrap())
                    .vid(vid)
                    .build(),
            )
            .build();

        validate_are_some!(app_config, bind_interface, physical_interface, stream).unwrap();

        app_config
    }

    fn generate_bridged_app_config(interface: String, vid: u16) -> BridgedApp {
        let app_config = BridgedAppBuilder::new()
            .vlans(vec![vid])
            .virtual_interface_bridge(format!("{interface}-br"))
            .virtual_interface_app(interface)
            .netns_app("somenetns".to_owned())
            .build();

        validate_are_some!(
            app_config,
            vlans,
            virtual_interface_app,
            netns_app,
            virtual_interface_bridge,
        )
        .unwrap();

        app_config
    }

    fn generate_stream_config(interface: String, vid: u16) -> Stream {
        let stream_config = StreamBuilder::new()
            .incoming_interfaces(vec![format!("{interface}-br")])
            .identifications(vec![StreamIdentificationBuilder::new()
                .destination_address("8b:de:82:a1:59:5a".parse().unwrap())
                .vid(vid)
                .build()])
            .outgoing_l2(vec![OutgoingL2Builder::new()
                .outgoing_interface(interface)
                .build()])
            .build();

        validate_are_some!(
            stream_config,
            incoming_interfaces,
            identifications,
            outgoing_l2
        )
        .unwrap();

        stream_config
    }

    fn generate_flow_config(interface: String, vid: u16) -> Flow {
        let flow_config = FlowBuilder::new()
            .incoming_app_flows(vec![AppFlowBuilder::new()
                .ingress_interfaces(vec![interface.clone()])
                .ingress_identification(
                    StreamIdentificationBuilder::new()
                        .destination_address("CB:cb:cb:cb:cb:AB".parse().unwrap())
                        .vid(vid)
                        .build(),
                )
                .build()])
            .outgoing_forwarding(vec![OutgoingForwardingBuilder::new()
                .mpls(MplsHeaderBuilder::new().label(1234).build())
                .ip(UdpIpHeaderBuilder::new()
                    .source("10.0.1.1".parse().unwrap())
                    .destination("10.0.1.2".parse().unwrap())
                    .source_port(3456)
                    .build())
                .outgoing_l2(vec![OutgoingL2Builder::new()
                    .outgoing_interface(interface)
                    .destination("CB:cb:cb:cb:cb:AB".parse().unwrap())
                    .priority(0)
                    .vid(vid)
                    .build()])
                .build()])
            .build();

        validate_are_some!(flow_config, incoming_app_flows, outgoing_forwarding,).unwrap();

        flow_config
    }

    fn configuration_happy(interface: String, vid: u16) -> MockConfiguration {
        let mut configuration = MockConfiguration::new();
        let interface2 = interface.clone();
        let interface3 = interface.clone();
        let interface4 = interface.clone();
        let interface5 = interface.clone();
        let interface6 = interface.clone();
        let interface7 = interface.clone();
        let interface8 = interface.clone();

        configuration
            .expect_get_interface()
            .returning(move |_| Ok(Some(generate_interface_config())));
        configuration.expect_get_interfaces().returning(move || {
            Ok(BTreeMap::from([(
                interface.clone(),
                generate_interface_config(),
            )]))
        });
        configuration
            .expect_get_unbridged_app()
            .returning(move |_| Ok(Some(generate_unbridged_app_config(interface2.clone(), vid))));
        configuration
            .expect_get_bridged_app()
            .returning(move |_| Ok(Some(generate_bridged_app_config(interface3.clone(), vid))));
        configuration
            .expect_get_stream()
            .returning(move |_| Ok(Some(generate_stream_config(interface4.clone(), vid))));
        configuration
            .expect_get_unbridged_apps()
            .returning(move || {
                Ok(BTreeMap::from([(
                    String::from("app0"),
                    generate_unbridged_app_config(interface5.clone(), vid),
                )]))
            });
        configuration.expect_get_bridged_apps().returning(move || {
            Ok(BTreeMap::from([(
                String::from("app0"),
                generate_bridged_app_config(interface6.clone(), vid),
            )]))
        });
        configuration.expect_get_streams().returning(move || {
            Ok(BTreeMap::from([(
                String::from("stream0"),
                generate_stream_config(interface7.clone(), vid),
            )]))
        });
        configuration.expect_get_flows().returning(move || {
            Ok(BTreeMap::from([(
                String::from("ssl-1"),
                generate_flow_config(interface8.clone(), vid),
            )]))
        });
        configuration
    }

    fn configuration_failing() -> MockConfiguration {
        let mut configuration = MockConfiguration::new();
        configuration
            .expect_get_interface()
            .returning(|_| Err(anyhow!("failed")));
        configuration
            .expect_get_interfaces()
            .returning(|| Err(anyhow!("failed")));
        configuration
            .expect_get_unbridged_app()
            .returning(|_| Err(anyhow!("failed")));
        configuration
            .expect_get_unbridged_apps()
            .returning(|| Err(anyhow!("failed")));
        configuration
            .expect_get_bridged_app()
            .returning(|_| Err(anyhow!("failed")));
        configuration
            .expect_get_bridged_apps()
            .returning(|| Err(anyhow!("failed")));
        configuration
    }

    fn queue_setup_happy() -> MockQueueSetup {
        let mut queue_setup = MockQueueSetup::new();
        queue_setup
            .expect_apply_config()
            .returning(move |_name, _config| Ok(()));
        queue_setup
    }

    fn queue_setup_failing() -> MockQueueSetup {
        let mut queue_setup = MockQueueSetup::new();
        queue_setup
            .expect_apply_config()
            .returning(|_, _| Err(anyhow!("failed")));
        queue_setup
    }

    fn data_plane_happy() -> MockDataPlane {
        let mut data_plane = MockDataPlane::new();
        data_plane.expect_setup_stream().returning(|_, _| Ok(()));
        data_plane.expect_setup_flow().returning(|_, _| Ok(()));
        data_plane.expect_load_xdp_pass().returning(|_| Ok(()));
        data_plane.expect_pin_xdp_pass().returning(|_| Ok(()));
        data_plane
    }

    fn data_plane_failing() -> MockDataPlane {
        let mut data_plane = MockDataPlane::new();
        data_plane
            .expect_setup_stream()
            .returning(|_, _| Err(anyhow!("failed")));
        data_plane
            .expect_setup_flow()
            .returning(|_, _| Err(anyhow!("failed")));
        data_plane
            .expect_load_xdp_pass()
            .returning(|_| Err(anyhow!("failed")));
        data_plane
            .expect_pin_xdp_pass()
            .returning(|_| Err(anyhow!("failed")));
        data_plane
    }

    fn dispatcher_happy() -> MockDispatcher {
        let mut dispatcher = MockDispatcher::new();
        dispatcher
            .expect_configure_stream()
            .returning(|_, _, _, _, _| Ok(()));
        dispatcher
            .expect_protect_stream()
            .returning(|_, _, _| Ok(()));
        dispatcher
            .expect_configure_best_effort()
            .returning(|_, _, _| Ok(()));
        dispatcher
    }

    fn dispatcher_failing() -> MockDispatcher {
        let mut dispatcher = MockDispatcher::new();
        dispatcher
            .expect_configure_stream()
            .returning(|_, _, _, _, _| Err(anyhow!("failed")));
        dispatcher
            .expect_protect_stream()
            .returning(|_, _, _| Err(anyhow!("failed")));
        dispatcher
            .expect_configure_best_effort()
            .returning(|_, _, _| Err(anyhow!("failed")));
        dispatcher
    }

    fn interface_setup_happy() -> MockInterfaceSetup {
        let mut interface_setup = MockInterfaceSetup::new();
        interface_setup
            .expect_set_link_state()
            .returning(move |_, _, _| Ok(()));
        interface_setup
            .expect_add_ip_address()
            .returning(move |_, _, _, _| Ok(()));
        interface_setup
            .expect_set_mac_address()
            .returning(move |_, _, _| Ok(()));
        interface_setup
            .expect_setup_vlan_interface()
            .returning(move |_, _, _| Ok(()));
        interface_setup
            .expect_setup_veth_pair_with_vlans()
            .returning(move |_, _, _, _| Ok(()));
        interface_setup
            .expect_set_vlan_offload()
            .returning(move |_, _, _, _| Ok(()));
        interface_setup
            .expect_attach_pinned_xdp()
            .returning(move |_, _, _| Ok(()));
        interface_setup
    }

    fn interface_setup_failing() -> MockInterfaceSetup {
        let mut interface_setup = MockInterfaceSetup::new();
        interface_setup
            .expect_set_link_state()
            .returning(|_, _, _| Err(anyhow!("failed")));
        interface_setup
            .expect_add_ip_address()
            .returning(|_, _, _, _| Err(anyhow!("failed")));
        interface_setup
            .expect_set_mac_address()
            .returning(|_, _, _| Err(anyhow!("failed")));
        interface_setup
            .expect_setup_vlan_interface()
            .returning(|_, _, _| Err(anyhow!("failed")));
        interface_setup
            .expect_setup_veth_pair_with_vlans()
            .returning(move |_, _, _, _| Err(anyhow!("failed")));
        interface_setup
            .expect_set_vlan_offload()
            .returning(move |_, _, _, _| Err(anyhow!("failed")));
        interface_setup
            .expect_attach_pinned_xdp()
            .returning(move |_, _, _| Err(anyhow!("failed")));
        interface_setup
    }

    #[tokio::test]
    async fn test_setup_happy() -> Result<()> {
        let interface = "ethxy";
        let vid = 43;
        let configuration = Arc::new(Mutex::new(configuration_happy(
            String::from(interface),
            vid,
        )));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy()));
        let data_plane = Arc::new(Mutex::new(data_plane_happy()));
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_happy()));
        let controller = Controller::new();
        controller
            .setup(
                configuration,
                queue_setup,
                data_plane,
                dispatcher,
                interface_setup,
            )
            .await?;
        Ok(())
    }

    #[tokio::test]
    #[should_panic(expected = "Fetching the configuration failed")]
    async fn test_setup_configuration_failure() {
        let configuration = Arc::new(Mutex::new(configuration_failing()));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy()));
        let data_plane = Arc::new(Mutex::new(data_plane_happy()));
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_happy()));
        let controller = Controller::new();
        controller
            .setup(
                configuration,
                queue_setup,
                data_plane,
                dispatcher,
                interface_setup,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Setting up the queue for abc failed")]
    async fn test_setup_queue_setup_failure() {
        let configuration = Arc::new(Mutex::new(configuration_happy(String::from("abc"), 4)));
        let queue_setup = Arc::new(Mutex::new(queue_setup_failing()));
        let data_plane = Arc::new(Mutex::new(data_plane_happy()));
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_happy()));
        let controller = Controller::new();
        controller
            .setup(
                configuration,
                queue_setup,
                data_plane,
                dispatcher,
                interface_setup,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Pinning dummy XDP failed")]
    async fn test_setup_data_plane_failure() {
        let configuration = Arc::new(Mutex::new(configuration_happy(String::from("abc"), 4)));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy()));
        let data_plane = Arc::new(Mutex::new(data_plane_failing()));
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_happy()));
        let controller = Controller::new();
        controller
            .setup(
                configuration,
                queue_setup,
                data_plane,
                dispatcher,
                interface_setup,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Installing protection on abc via the dispatcher failed")]
    async fn test_setup_dispatcher_failure() {
        let configuration = Arc::new(Mutex::new(configuration_happy(String::from("abc"), 4)));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy()));
        let data_plane = Arc::new(Mutex::new(data_plane_happy()));
        let dispatcher = Arc::new(Mutex::new(dispatcher_failing()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_happy()));
        let controller = Controller::new();
        controller
            .setup(
                configuration,
                queue_setup,
                data_plane,
                dispatcher,
                interface_setup,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Setting up veth pair for app0 failed")]
    async fn test_setup_interface_setup_failure() {
        let configuration = Arc::new(Mutex::new(configuration_happy(String::from("abc"), 4)));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy()));
        let data_plane = Arc::new(Mutex::new(data_plane_happy()));
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_failing()));
        let controller = Controller::new();
        controller
            .setup(
                configuration,
                queue_setup,
                data_plane,
                dispatcher,
                interface_setup,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_protect_happy() -> Result<()> {
        let interface = "ethxy";
        let vid = 43;
        let configuration = Arc::new(Mutex::new(configuration_happy(
            String::from(interface),
            vid,
        )));
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let controller = Controller::new();
        controller
            .protect(
                "app123",
                &PathBuf::from("cgroup"),
                configuration,
                dispatcher,
            )
            .await?;
        Ok(())
    }

    #[tokio::test]
    #[should_panic(expected = "Installing protection via the dispatcher failed")]
    async fn test_protect_dispatcher_failing() {
        let interface = "ethxy";
        let vid = 43;
        let configuration = Arc::new(Mutex::new(configuration_happy(
            String::from(interface),
            vid,
        )));
        let dispatcher = Arc::new(Mutex::new(dispatcher_failing()));
        let controller = Controller::new();
        controller
            .protect(
                "app123",
                &PathBuf::from("cgroup"),
                configuration,
                dispatcher,
            )
            .await
            .unwrap();
    }
}
