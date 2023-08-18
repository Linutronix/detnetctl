// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Core component of the node controller
//!
//! The controller is combining the configuration, the NIC setup and the dispatcher
//! to perform a complete registration of an application.
//!
//! ```
//! use detnetctl::configuration::{Configuration, YAMLConfiguration};
//! use detnetctl::controller::{Controller, Registration};
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
//! use std::sync::Arc;
//!
//! # tokio_test::block_on(async {
//! let controller = Controller::new();
//! let mut configuration = Arc::new(Mutex::new(YAMLConfiguration::new()));
//! configuration.lock().await.read(File::open(filepath)?)?;
//! let mut queue_setup = Arc::new(Mutex::new(DummyQueueSetup::new(3)));
//! let mut dispatcher = Arc::new(Mutex::new(DummyDispatcher));
//! let mut interface_setup = Arc::new(Mutex::new(DummyInterfaceSetup));
//! let response = controller
//!     .register("app0", configuration, queue_setup, dispatcher, interface_setup)
//!     .await?;
//! # Ok::<(), anyhow::Error>(())
//! # });
//! # Ok::<(), anyhow::Error>(())
//! ```

use crate::configuration::{AppConfig, Configuration};
use crate::dispatcher::{Dispatcher, StreamIdentification};
use crate::interface_setup::{InterfaceSetup, LinkState};
use crate::queue_setup::QueueSetup;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use futures::lock::Mutex;
use getrandom::getrandom;
use std::sync::Arc;
use tokio::time::Instant;

/// The reponse of a registration to be passed back to the application
/// for setting up the socket appropriately.
#[derive(Debug)]
pub struct RegisterResponse {
    /// Logical interface for the application to bind to (usually a VLAN interface like eth0.2)
    pub logical_interface: String,
    /// The token to set via SO_TOKEN
    pub token: u64,
}

/// Defines a registration operation
#[async_trait]
pub trait Registration {
    /// Register an application including the following steps
    ///
    /// 1. Generate a random token
    /// 2. Fetch the configuration corresponding to the `app_name`
    /// 3. Set up the NIC according to the configuration
    /// 4. Set up the dispatcher to prevent interfering messages from other applications
    /// 5. Return the appropriate socket settings for the application
    async fn register(
        &self,
        app_name: &str,
        mut configuration: Arc<Mutex<dyn Configuration + Send>>,
        queue_setup: Arc<Mutex<dyn QueueSetup + Send>>,
        mut dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
        mut interface_setup: Arc<Mutex<dyn InterfaceSetup + Sync + Send>>,
    ) -> Result<RegisterResponse>;
}

/// Struct to perform the registration on
#[derive(Default)]
pub struct Controller;

impl Controller {
    /// Create a new controller
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Registration for Controller {
    async fn register(
        &self,
        app_name: &str,
        configuration: Arc<Mutex<dyn Configuration + Send>>,
        queue_setup: Arc<Mutex<dyn QueueSetup + Send>>,
        dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
        interface_setup: Arc<Mutex<dyn InterfaceSetup + Sync + Send>>,
    ) -> Result<RegisterResponse> {
        let start = Instant::now();
        println!("Request to register {app_name}");

        // Generate token
        let token = generate_token()?;

        // Fetch configuration for app
        let app_config = configuration
            .lock()
            .await
            .get_app_config(app_name)
            .context("Fetching the configuration failed")?;
        println!("  Fetched from configuration module: {app_config:#?}");

        let locked_interface_setup = interface_setup.lock().await;

        let setup_result = setup(
            &app_config,
            token,
            queue_setup,
            dispatcher,
            &*locked_interface_setup,
        )
        .await; // No ? since we need to ensure that the link is up again even after error

        let if_up_result = set_interfaces_up(&app_config, &*locked_interface_setup).await;

        // The first occurred error shall be returned, but a potential second still be printed
        if let Err(if_up_error) = if_up_result {
            return match setup_result {
                Ok(_) => Err(if_up_error),
                Err(setup_error) => {
                    eprintln!("After setup failed, interface up failed, too: {if_up_error}");
                    Err(setup_error)
                }
            };
        }

        setup_result?;

        println!("  Finished after {:.1?}", start.elapsed());

        Ok(RegisterResponse {
            logical_interface: app_config.logical_interface,
            token,
        })
    }
}

/// Securely generate a random token
fn generate_token() -> Result<u64> {
    let mut token_bytes = [0; 8];
    getrandom(&mut token_bytes)?;
    Ok(u64::from_be_bytes(token_bytes))
}

async fn setup(
    app_config: &AppConfig,
    token: u64,
    queue_setup: Arc<Mutex<dyn QueueSetup + Send>>,
    dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
    interface_setup: &(dyn InterfaceSetup + Sync + Send),
) -> Result<()> {
    interface_setup
        .set_link_state(LinkState::Down, &app_config.physical_interface)
        .await
        .with_context(|| {
            format!(
                "Setting interface {} down failed",
                &app_config.physical_interface
            )
        })?;
    println!("  Interface {} down", app_config.physical_interface);

    // Setup Queue
    let queue_setup_response = queue_setup
        .lock()
        .await
        .apply_config(app_config)
        .context("Setting up the queue failed")?;
    println!("  Result of queue setup: {queue_setup_response:#?}");

    // Assemble stream identification
    let stream_id = StreamIdentification {
        destination_address: app_config.destination_address.ok_or_else(|| {
            anyhow!("Streams without destination address can currently not be handled")
        })?,
        vlan_identifier: app_config
            .vid
            .ok_or_else(|| anyhow!("Streams without VLAN ID can currently not be handled"))?,
    };

    let pcp = app_config
        .pcp
        .ok_or_else(|| anyhow!("PCP configuration is missing"))?;

    // Setup BPF Hooks
    // It is important to use the physical interface (eth0) and not the logical interface (eth0.2)
    // here, because otherwise it would be possible to use a different logical interface,
    // but same SO_PRIORITY and physical interface. Even though it would not be routed to the
    // same VLAN it could still block the time slot!
    let mut locked_dispatcher = dispatcher.lock().await;
    locked_dispatcher
        .configure_stream(
            &app_config.physical_interface,
            &stream_id,
            queue_setup_response.priority,
            pcp,
            Some(token),
        )
        .context("Installing protection via the dispatcher failed. SO_TOKEN patch missing?")?;
    println!(
        "  Dispatcher installed for stream {:#?} with priority {} on {}",
        stream_id, queue_setup_response.priority, app_config.physical_interface
    );

    // Setup logical interface
    if let Some(vid) = app_config.vid {
        interface_setup
            .setup_vlan_interface(
                &app_config.physical_interface,
                &app_config.logical_interface,
                vid,
            )
            .await
            .context("Setting up VLAN interface failed")?;
        println!(
            "  VLAN interface {} properly configured",
            app_config.logical_interface
        );
    }

    // Add address to logical interface
    if let Some(addresses) = &app_config.addresses {
        for (ip, prefix_length) in addresses {
            interface_setup
                .add_address(*ip, *prefix_length, &app_config.logical_interface)
                .await
                .context("Adding address to VLAN interface failed")?;
            println!(
                "  Added {}/{} to {}",
                ip, prefix_length, app_config.logical_interface
            );
        }
    } else {
        println!("  No IP address configured, since none was provided");
    }

    Ok(())
}

async fn set_interfaces_up(
    app_config: &AppConfig,
    interface_setup: &(dyn InterfaceSetup + Sync + Send),
) -> Result<()> {
    interface_setup
        .set_link_state(LinkState::Up, &app_config.physical_interface)
        .await
        .with_context(|| {
            format!(
                "Setting interface {} up failed",
                &app_config.physical_interface
            )
        })?;
    println!("  Interface {} up", app_config.physical_interface);

    interface_setup
        .set_link_state(LinkState::Up, &app_config.logical_interface)
        .await
        .with_context(|| {
            format!(
                "Setting interface {} up failed",
                &app_config.logical_interface
            )
        })?;
    println!("  Interface {} up", app_config.logical_interface);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{AppConfig, MockConfiguration};
    use crate::dispatcher::MockDispatcher;
    use crate::interface_setup::MockInterfaceSetup;
    use crate::queue_setup::{MockQueueSetup, QueueSetupResponse};
    use anyhow::anyhow;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_token_unique() -> Result<()> {
        let first_token = generate_token()?;
        let second_token = generate_token()?;
        assert_ne!(first_token, second_token);
        Ok(())
    }

    fn configuration_happy(interface: String, vid: u16) -> MockConfiguration {
        let mut configuration = MockConfiguration::new();
        configuration.expect_get_app_config().returning(move |_| {
            Ok(AppConfig {
                logical_interface: format!("{interface}.{vid}"),
                physical_interface: interface.clone(),
                period_ns: Some(0),
                offset_ns: Some(0),
                size_bytes: Some(0),
                destination_address: Some("8b:de:82:a1:59:5a".parse()?),
                vid: Some(vid),
                pcp: Some(4),
                addresses: Some(vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 3)), 16)]),
            })
        });
        configuration
    }

    fn configuration_failing() -> MockConfiguration {
        let mut configuration = MockConfiguration::new();
        configuration
            .expect_get_app_config()
            .returning(|_| Err(anyhow!("failed")));
        configuration
    }

    fn queue_setup_happy(priority: u32) -> MockQueueSetup {
        let mut queue_setup = MockQueueSetup::new();
        queue_setup.expect_apply_config().returning(move |config| {
            Ok(QueueSetupResponse {
                logical_interface: config.logical_interface.clone(),
                priority,
            })
        });
        queue_setup
    }

    fn queue_setup_failing() -> MockQueueSetup {
        let mut queue_setup = MockQueueSetup::new();
        queue_setup
            .expect_apply_config()
            .returning(|_| Err(anyhow!("failed")));
        queue_setup
    }

    fn dispatcher_happy() -> MockDispatcher {
        let mut dispatcher = MockDispatcher::new();
        dispatcher
            .expect_configure_stream()
            .returning(|_, _, _, _, _| Ok(()));
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
    async fn test_register_happy() -> Result<()> {
        let interface = "ethxy";
        let vid = 43;
        let priority = 32;
        let configuration = Arc::new(Mutex::new(configuration_happy(
            String::from(interface),
            vid,
        )));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy(priority)));
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_happy()));
        let controller = Controller::new();
        let response = controller
            .register(
                "app123",
                configuration,
                queue_setup,
                dispatcher,
                interface_setup,
            )
            .await?;
        assert_eq!(response.logical_interface, format!("{interface}.{vid}"));
        assert!(response.token > 10); // not GUARANTEED, but VERY unlikely to fail
        Ok(())
    }

    #[tokio::test]
    #[should_panic(expected = "Fetching the configuration failed")]
    async fn test_register_configuration_failure() {
        let configuration = Arc::new(Mutex::new(configuration_failing()));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy(32)));
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_happy()));
        let controller = Controller::new();
        controller
            .register(
                "app123",
                configuration,
                queue_setup,
                dispatcher,
                interface_setup,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Setting up the queue failed")]
    async fn test_register_queue_setup_failure() {
        let configuration = Arc::new(Mutex::new(configuration_happy(String::from("abc"), 4)));
        let queue_setup = Arc::new(Mutex::new(queue_setup_failing()));
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_happy()));
        let controller = Controller::new();
        controller
            .register(
                "app123",
                configuration,
                queue_setup,
                dispatcher,
                interface_setup,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Installing protection via the dispatcher failed")]
    async fn test_register_dispatcher_failure() {
        let configuration = Arc::new(Mutex::new(configuration_happy(String::from("abc"), 4)));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy(32)));
        let dispatcher = Arc::new(Mutex::new(dispatcher_failing()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_happy()));
        let controller = Controller::new();
        controller
            .register(
                "app123",
                configuration,
                queue_setup,
                dispatcher,
                interface_setup,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Setting interface abc down failed")]
    async fn test_register_interface_setup_failure() {
        let configuration = Arc::new(Mutex::new(configuration_happy(String::from("abc"), 4)));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy(32)));
        let dispatcher = Arc::new(Mutex::new(dispatcher_happy()));
        let interface_setup = Arc::new(Mutex::new(interface_setup_failing()));
        let controller = Controller::new();
        controller
            .register(
                "app123",
                configuration,
                queue_setup,
                dispatcher,
                interface_setup,
            )
            .await
            .unwrap();
    }
}
