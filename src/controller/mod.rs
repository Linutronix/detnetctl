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

use crate::configuration::{
    BridgedApp, Configuration, FillDefaults, Interface, Stream, StreamIdentification, UnbridgedApp,
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
}

struct ExpandedConfiguration {
    interfaces: BTreeMap<String, ExpandedInterface>,
    bridged_apps: BTreeMap<String, BridgedApp>,
    streams: Vec<Stream>,
}

async fn fetch_expanded_configuration(
    configuration: Arc<Mutex<dyn Configuration + Send>>,
) -> Result<ExpandedConfiguration> {
    let mut config = configuration.lock().await;

    let mut interfaces = config.get_interfaces()?;
    let mut unbridged_apps = config.get_unbridged_apps()?;
    let mut bridged_apps = config.get_bridged_apps()?;
    let mut streams = config.get_streams()?;

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
        validate_are_some!(stream, incoming_interface, identification, outgoing_l2)?;
    }

    println!("Fetched from configuration module:");
    println!("Interfaces: {interfaces:#?}");
    println!("Unbridged Apps: {unbridged_apps:#?}");
    println!("Bridged Apps: {bridged_apps:#?}");
    println!("Streams: {streams:#?}");

    Ok(ExpandedConfiguration {
        interfaces: collect_expanded_interfaces(&interfaces, &unbridged_apps, &streams)?,
        bridged_apps,
        streams: streams.into_values().collect(),
    })
}

fn collect_expanded_interfaces(
    interfaces: &BTreeMap<String, Interface>,
    unbridged_apps: &BTreeMap<String, UnbridgedApp>,
    streams: &BTreeMap<String, Stream>,
) -> Result<BTreeMap<String, ExpandedInterface>> {
    interfaces
        .iter()
        .map(|(name, ifconfig)| -> Result<(String, ExpandedInterface)> {
            // find all matching streams to protect from coming via TC
            let mut streams_to_protect = vec![];
            for stream in streams.values() {
                if stream.outgoing_l2()?.outgoing_interface()? == name {
                    streams_to_protect.push(stream.identification()?.clone());
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
                },
            ))
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
                    app_config.virtual_interface_bridge()?,
                    app_config.vlans_opt().unwrap_or(&vec![]),
                )
                .await
                .with_context(|| format!("Setting up veth pair for {name} failed"))?;

            // Load dummy XDP for app side of veth
            // pair, otherwise traffic redirected
            // via XDP is not handled
            let mut locked_data_plane = data_plane.lock().await;
            locked_data_plane
                .load_xdp_pass(virtual_interface_app)
                .with_context(|| {
                    format!("Installing dummy XDP on {virtual_interface_app} failed")
                })?;
        }

        // Install all XDPs for the streams
        {
            let mut locked_data_plane = data_plane.lock().await;
            for stream in &config.streams {
                locked_data_plane
                    .setup_stream(stream)
                    .context("Installing stream via XDP failed")?;
            }
        }

        // Configure IP addresses and promiscuous mode
        {
            let locked_interface_setup = interface_setup.lock().await;
            for (name, interface) in &config.interfaces {
                if let Some(addresses) = &interface.config.addresses_opt() {
                    for (ip, prefix_length) in *addresses {
                        locked_interface_setup
                            .add_address(*ip, *prefix_length, name)
                            .await
                            .context("Adding address to interface failed")?;
                        println!("  Added {ip}/{prefix_length} to {name}");
                    }
                }

                if let Some(promiscuous) = interface.config.promiscuous_opt() {
                    locked_interface_setup
                        .set_promiscuous(name, *promiscuous)
                        .await
                        .with_context(|| {
                            format!("Setting interface {name} to promiscious mode failed")
                        })?;
                }
            }
        }

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

            let if_up_result =
                set_interface_state(name, LinkState::Up, &*locked_interface_setup).await;

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
                    &*locked_interface_setup,
                )
                .await?;
            }
        }

        move_veths_to_namespaces(&config, &interface_setup).await?;

        // Finally set the bridge side of the veth pair up.
        // The other side needs to be set up by the user
        // inside the namespace, since it cannot be set up
        // from this process.
        set_veth_bridge_side_up(&config, &interface_setup).await?;

        println!("  Finished after {:.1?}", start.elapsed());

        Ok(())
    }
}

async fn move_veths_to_namespaces(
    config: &ExpandedConfiguration,
    interface_setup: &Arc<Mutex<dyn InterfaceSetup + Sync + Send>>,
) -> Result<()> {
    for app_config in config.bridged_apps.values() {
        let interface = app_config.virtual_interface_app()?;

        let locked_interface_setup = interface_setup.lock().await;

        if let Some(vids) = app_config.vlans_opt() {
            for vid in vids {
                locked_interface_setup
                    .move_to_network_namespace(
                        &format!("{interface}.{vid}"),
                        app_config.netns_app()?,
                    )
                    .await?;
            }
        }

        locked_interface_setup
            .move_to_network_namespace(interface, app_config.netns_app()?)
            .await?;
    }

    Ok(())
}

async fn set_veth_bridge_side_up(
    config: &ExpandedConfiguration,
    interface_setup: &Arc<Mutex<dyn InterfaceSetup + Sync + Send>>,
) -> Result<()> {
    for app_config in config.bridged_apps.values() {
        let locked_interface_setup = interface_setup.lock().await;
        set_interface_state(
            app_config.virtual_interface_bridge()?,
            LinkState::Up,
            &*locked_interface_setup,
        )
        .await?;
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
    set_interface_state(interface_name, LinkState::Down, interface_setup).await?;

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

    // Protect all configured streams from coming via TC, they shall only come via XDP
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
    interface_setup: &(dyn InterfaceSetup + Sync + Send),
) -> Result<()> {
    interface_setup
        .set_link_state(state, interface)
        .await
        .with_context(|| format!("Setting interface {interface} {state} failed"))?;
    println!("  Interface {interface} {state}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
            .addresses(vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 3)), 16)])
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
            .incoming_interface(format!("{interface}-br"))
            .identification(
                StreamIdentificationBuilder::new()
                    .destination_address("8b:de:82:a1:59:5a".parse().unwrap())
                    .vid(vid)
                    .build(),
            )
            .outgoing_l2(
                OutgoingL2Builder::new()
                    .outgoing_interface(interface)
                    .build(),
            )
            .build();

        validate_are_some!(
            stream_config,
            incoming_interface,
            identification,
            outgoing_l2
        )
        .unwrap();

        stream_config
    }

    fn configuration_happy(interface: String, vid: u16) -> MockConfiguration {
        let mut configuration = MockConfiguration::new();
        let interface2 = interface.clone();
        let interface3 = interface.clone();
        let interface4 = interface.clone();
        let interface5 = interface.clone();
        let interface6 = interface.clone();
        let interface7 = interface.clone();

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
        data_plane.expect_setup_stream().returning(|_| Ok(()));
        data_plane.expect_load_xdp_pass().returning(|_| Ok(()));
        data_plane
    }

    fn data_plane_failing() -> MockDataPlane {
        let mut data_plane = MockDataPlane::new();
        data_plane
            .expect_setup_stream()
            .returning(|_| Err(anyhow!("failed")));
        data_plane
            .expect_load_xdp_pass()
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
            .returning(move |_, _| Ok(()));
        interface_setup
            .expect_add_address()
            .returning(move |_, _, _| Ok(()));
        interface_setup
            .expect_setup_vlan_interface()
            .returning(move |_, _, _| Ok(()));
        interface_setup
            .expect_setup_veth_pair_with_vlans()
            .returning(move |_, _, _| Ok(()));
        interface_setup
            .expect_move_to_network_namespace()
            .returning(move |_, _| Ok(()));
        interface_setup
    }

    fn interface_setup_failing() -> MockInterfaceSetup {
        let mut interface_setup = MockInterfaceSetup::new();
        interface_setup
            .expect_set_link_state()
            .returning(|_, _| Err(anyhow!("failed")));
        interface_setup
            .expect_add_address()
            .returning(|_, _, _| Err(anyhow!("failed")));
        interface_setup
            .expect_setup_vlan_interface()
            .returning(|_, _, _| Err(anyhow!("failed")));
        interface_setup
            .expect_setup_veth_pair_with_vlans()
            .returning(move |_, _, _| Err(anyhow!("failed")));
        interface_setup
            .expect_move_to_network_namespace()
            .returning(move |_, _| Err(anyhow!("failed")));
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
    #[should_panic(expected = "Installing dummy XDP on abc failed")]
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
