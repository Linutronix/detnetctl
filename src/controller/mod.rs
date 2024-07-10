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
//! use detnetctl::controller::{Controller, Setup, Protection};
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
//! let mut dispatcher = Arc::new(Mutex::new(DummyDispatcher));
//! let mut interface_setup = Arc::new(Mutex::new(DummyInterfaceSetup));
//! controller
//!     .setup(configuration.clone(), queue_setup, dispatcher.clone(), interface_setup)
//!     .await?;
//! controller
//!     .protect("app0", &cgroup, configuration, dispatcher)
//!     .await?;
//! # Ok::<(), anyhow::Error>(())
//! # });
//! # Ok::<(), anyhow::Error>(())
//! ```

use crate::configuration::{AppConfig, Configuration, FillDefaults, Interface};
use crate::dispatcher::Dispatcher;
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
        mut dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
        mut interface_setup: Arc<Mutex<dyn InterfaceSetup + Sync + Send>>,
    ) -> Result<()>;
}

/// Defines a protection operation
#[async_trait]
pub trait Protection {
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

async fn fetch_configurations(
    configuration: Arc<Mutex<dyn Configuration + Send>>,
) -> Result<(BTreeMap<String, Interface>, BTreeMap<String, AppConfig>)> {
    let mut config = configuration.lock().await;
    Ok((config.get_interfaces()?, config.get_app_configs()?))
}

#[async_trait]
impl Setup for Controller {
    async fn setup(
        &self,
        configuration: Arc<Mutex<dyn Configuration + Send>>,
        queue_setup: Arc<Mutex<dyn QueueSetup + Send>>,
        dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
        interface_setup: Arc<Mutex<dyn InterfaceSetup + Sync + Send>>,
    ) -> Result<()> {
        let start = Instant::now();
        println!("Setup of DetNet system");

        // Fetch configurations for interfaces and apps
        let (mut interface_configs, mut app_configs) = fetch_configurations(configuration.clone())
            .await
            .context("Fetching the configuration failed")?;

        for interface_config in interface_configs.values_mut() {
            interface_config.fill_defaults()?;
            if interface_config.schedule_opt().is_some() {
                validate_are_some!(interface_config, schedule, taprio, pcp_encoding)?;
            }
        }

        for app_config in app_configs.values_mut() {
            app_config.fill_defaults()?;
            validate_are_some!(
                app_config,
                physical_interface,
                logical_interface,
                stream,
                priority
            )?;
        }

        println!("  Fetched from configuration module: {interface_configs:#?} {app_configs:#?}");

        // Configure IP addresses
        {
            let locked_interface_setup = interface_setup.lock().await;
            for (interface_name, interface_config) in &interface_configs {
                if let Some(addresses) = &interface_config.addresses_opt() {
                    for (ip, prefix_length) in *addresses {
                        locked_interface_setup
                            .add_address(*ip, *prefix_length, interface_name)
                            .await
                            .context("Adding address to interface failed")?;
                        println!("  Added {ip}/{prefix_length} to {interface_name}");
                    }
                }
            }
        }

        // Iterate over all interfaces with schedule configuration
        // By this approach, instead of iterating over the app_configs,
        // we need to setup each interface only once.
        for (interface_name, interface_config) in interface_configs {
            if interface_config.schedule_opt().is_none() {
                continue;
            }

            let locked_interface_setup = interface_setup.lock().await;

            let app_configs_for_interface = app_configs.iter().try_fold(
                BTreeMap::default(),
                |mut acc, (app_name, app_config)| -> Result<BTreeMap<&String, &AppConfig>> {
                    if app_config.physical_interface()? == &interface_name {
                        acc.insert(app_name, app_config);
                    }

                    Ok(acc)
                },
            )?;

            let setup_result = setup_before_interface_up(
                &interface_name,
                &interface_config,
                &app_configs_for_interface,
                queue_setup.clone(),
                dispatcher.clone(),
                &*locked_interface_setup,
            )
            .await; // No ? since we need to ensure that the link is up again even after error

            let if_up_result =
                set_interface_state(&interface_name, LinkState::Up, &*locked_interface_setup).await;

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
            for app_config in app_configs.values() {
                set_interface_state(
                    app_config.logical_interface()?,
                    LinkState::Up,
                    &*locked_interface_setup,
                )
                .await?;
            }
        }

        println!("  Finished after {:.1?}", start.elapsed());

        Ok(())
    }
}

#[async_trait]
impl Protection for Controller {
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
            .get_app_config(app_name)
            .context("Fetching the configuration failed")?
            .ok_or_else(|| anyhow!("No configuration found for {app_name}"))?;
        println!("  Fetched from configuration module: {app_config:#?}");

        let stream_id = app_config.stream()?;

        let physical_interface = app_config.physical_interface()?;

        let mut locked_dispatcher = dispatcher.lock().await;
        locked_dispatcher
            .protect_stream(physical_interface, stream_id, Some(cgroup.into()))
            .context("Installing protection via the dispatcher failed")?;
        println!("  Protection installed for stream {stream_id:#?} on {physical_interface}");

        Ok(())
    }
}

async fn setup_before_interface_up(
    interface: &str,
    interface_config: &Interface,
    app_configs: &BTreeMap<&String, &AppConfig>,
    queue_setup: Arc<Mutex<dyn QueueSetup + Send>>,
    dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
    interface_setup: &(dyn InterfaceSetup + Sync + Send),
) -> Result<()> {
    set_interface_state(interface, LinkState::Down, interface_setup).await?;

    // Setup Queue
    queue_setup
        .lock()
        .await
        .apply_config(interface, interface_config)
        .await
        .context("Setting up the queue failed")?;
    println!("  Queues set up");

    for app_config in app_configs.values() {
        let logical_interface = app_config.logical_interface()?;
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
                interface,
                stream_id,
                (*priority).into(),
                Some(
                    *interface_config
                        .pcp_encoding()?
                        .pcp_from_priority(*priority)?,
                ),
                app_config
                    .cgroup_opt()
                    .map(|c| <PathBuf as AsRef<Path>>::as_ref(c).into()),
            )
            .context("Installing protection via the dispatcher failed")?;
        println!(
            "  Dispatcher installed for stream {stream_id:#?} with priority {priority} on {interface}",
        );

        if let Some(cgroup) = &app_config.cgroup_opt() {
            println!("  with protection for cgroup {cgroup:?}");
        }

        // Setup logical interface
        if let Some(vid) = stream_id.vid_opt() {
            interface_setup
                .setup_vlan_interface(interface, logical_interface, *vid)
                .await
                .context("Setting up VLAN interface failed")?;
            println!("  VLAN interface {logical_interface} properly configured");
        }
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
        AppConfig, AppConfigBuilder, GateControlEntryBuilder, GateOperation, InterfaceBuilder,
        MockConfiguration, Mode, QueueMapping, ScheduleBuilder, StreamIdentificationBuilder,
        TaprioConfigBuilder,
    };
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

    fn generate_app_config(interface: String, vid: u16) -> AppConfig {
        let app_config = AppConfigBuilder::new()
            .logical_interface(format!("{interface}.{vid}"))
            .physical_interface(interface)
            .stream(
                StreamIdentificationBuilder::new()
                    .destination_address("8b:de:82:a1:59:5a".parse().unwrap())
                    .vid(vid)
                    .build(),
            )
            .build();

        validate_are_some!(app_config, logical_interface, physical_interface, stream,).unwrap();

        app_config
    }

    fn configuration_happy(interface: String, vid: u16) -> MockConfiguration {
        let mut configuration = MockConfiguration::new();
        let interface2 = interface.clone();
        let interface3 = interface.clone();
        configuration
            .expect_get_interface()
            .returning(move |_| Ok(Some(generate_interface_config())));
        configuration.expect_get_interfaces().returning(move || {
            Ok(BTreeMap::from([(
                interface3.clone(),
                generate_interface_config(),
            )]))
        });
        configuration
            .expect_get_app_config()
            .returning(move |_| Ok(Some(generate_app_config(interface.clone(), vid))));
        configuration.expect_get_app_configs().returning(move || {
            Ok(BTreeMap::from([(
                String::from("app0"),
                generate_app_config(interface2.clone(), vid),
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
            .expect_get_app_config()
            .returning(|_| Err(anyhow!("failed")));
        configuration
            .expect_get_app_configs()
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
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_happy()));
        let controller = Controller::new();
        controller
            .setup(configuration, queue_setup, dispatcher, interface_setup)
            .await?;
        Ok(())
    }

    #[tokio::test]
    #[should_panic(expected = "Fetching the configuration failed")]
    async fn test_setup_configuration_failure() {
        let configuration = Arc::new(Mutex::new(configuration_failing()));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy()));
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_happy()));
        let controller = Controller::new();
        controller
            .setup(configuration, queue_setup, dispatcher, interface_setup)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Setting up the queue failed")]
    async fn test_setup_queue_setup_failure() {
        let configuration = Arc::new(Mutex::new(configuration_happy(String::from("abc"), 4)));
        let queue_setup = Arc::new(Mutex::new(queue_setup_failing()));
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_happy()));
        let controller = Controller::new();
        controller
            .setup(configuration, queue_setup, dispatcher, interface_setup)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Installing protection via the dispatcher failed")]
    async fn test_setup_dispatcher_failure() {
        let configuration = Arc::new(Mutex::new(configuration_happy(String::from("abc"), 4)));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy()));
        let dispatcher = Arc::new(Mutex::new(dispatcher_failing()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_happy()));
        let controller = Controller::new();
        controller
            .setup(configuration, queue_setup, dispatcher, interface_setup)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Adding address to interface failed")]
    async fn test_setup_interface_setup_failure() {
        let configuration = Arc::new(Mutex::new(configuration_happy(String::from("abc"), 4)));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy()));
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_failing()));
        let controller = Controller::new();
        controller
            .setup(configuration, queue_setup, dispatcher, interface_setup)
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
