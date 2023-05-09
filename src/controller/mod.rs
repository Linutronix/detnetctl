//! Core component of the node controller
//!
//! The controller is combining the configuration, the NIC setup and the guard
//! to perform a complete registration of an application.
//!
//! ```
//! use detnetctl::controller::{Registration, Controller};
//! use detnetctl::configuration::{Configuration, YAMLConfiguration};
//! use detnetctl::queue_setup::{QueueSetup, DummyQueueSetup};
//! use detnetctl::guard::{Guard, DummyGuard};
//!
//! # #[path = "../configuration/doctest.rs"]
//! # mod doctest;
//! # let tmpfile = doctest::generate_example_yaml();
//! # let filepath = tmpfile.path();
//! use std::fs::File;
//! use std::sync::Arc;
//! use futures::lock::Mutex;
//!
//! # tokio_test::block_on(async {
//! let controller = Controller::new();
//! let mut configuration = Arc::new(Mutex::new(YAMLConfiguration::new()));
//! configuration.lock().await.read(File::open(filepath)?)?;
//! let mut queue_setup = Arc::new(Mutex::new(DummyQueueSetup::new(3)));
//! let mut guard = Arc::new(Mutex::new(DummyGuard::new()));
//! let response = controller.register("app0", configuration, queue_setup, guard).await?;
//! # Ok::<(), anyhow::Error>(())
//! # });
//! # Ok::<(), anyhow::Error>(())
//! ```

use crate::configuration::Configuration;
use crate::guard::Guard;
use crate::queue_setup::QueueSetup;
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::lock::Mutex;
use getrandom::getrandom;
use std::sync::Arc;

/// The reponse of a registration to be passed back to the application
/// for setting up the socket appropriately.
#[derive(Debug)]
pub struct RegisterResponse {
    /// Logical interface for the application to bind to (usually a VLAN interface like eth0.2)
    pub logical_interface: String,
    /// The priority to set via SO_PRIORITY
    pub priority: u8,
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
    /// 4. Set up the guard to prevent interfering messages from other applications
    /// 5. Return the appropriate socket settings for the application
    ///
    async fn register(
        &self,
        app_name: &str,
        mut configuration: Arc<Mutex<dyn Configuration + Send>>,
        queue_setup: Arc<Mutex<dyn QueueSetup + Send>>,
        mut guard: Arc<Mutex<dyn Guard + Send>>,
    ) -> Result<RegisterResponse>;
}

/// Struct to perform the registration on
#[derive(Default)]
pub struct Controller;

impl Controller {
    /// Create a new controller
    pub fn new() -> Self {
        Self
    }

    /// Securely generate a random token
    fn generate_token(&self) -> Result<u64> {
        let mut token_bytes = [0; 8];
        getrandom(&mut token_bytes)?;
        Ok(u64::from_be_bytes(token_bytes))
    }
}

#[async_trait]
impl Registration for Controller {
    async fn register(
        &self,
        app_name: &str,
        configuration: Arc<Mutex<dyn Configuration + Send>>,
        queue_setup: Arc<Mutex<dyn QueueSetup + Send>>,
        guard: Arc<Mutex<dyn Guard + Send>>,
    ) -> Result<RegisterResponse> {
        println!("Request to register {}", app_name);

        // Generate token
        let token = self.generate_token()?;

        // Fetch configuration for app
        let app_config = configuration
            .lock()
            .await
            .get_app_config(app_name)
            .context("Fetching the configuration failed")
            .map_err(|e| {
                // print here and forward, otherwise the error would only be sent back to the application
                eprintln!("{:#}", e);
                e
            })?;
        println!("Fetched from configuration module: {:#?}", app_config);

        // Setup NIC
        let socket_config = queue_setup
            .lock()
            .await
            .apply_config(&app_config)
            .context("Setting up the queues failed")
            .map_err(|e| {
                eprintln!("{:#}", e);
                e
            })?;
        println!("Result of queue setup: {:#?}", socket_config);

        // Setup BPF Hooks
        // It is important to use the physical interface (eth0) and not the logical interface (eth0.2)
        // here, because otherwise it would be possible to use a different logical interface,
        // but same SO_PRIORITY and physical interface. Even though it would not be routed to the
        // same VLAN it could still block the time slot!
        let mut locked_guard = guard.lock().await;
        locked_guard
            .protect_priority(
                &app_config.physical_interface,
                socket_config.priority,
                token,
            )
            .context("Installing protection via the guard failed. SO_TOKEN patch missing?")
            .map_err(|e| {
                eprintln!("{:#}", e);
                e
            })?;

        Ok(RegisterResponse {
            logical_interface: socket_config.logical_interface,
            priority: socket_config.priority,
            token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{AppConfig, MockConfiguration};
    use crate::guard::MockGuard;
    use crate::queue_setup::{MockQueueSetup, SocketConfig};
    use anyhow::anyhow;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_token_unique() -> Result<()> {
        let controller = Controller::new();
        let first_token = controller.generate_token()?;
        let second_token = controller.generate_token()?;
        assert_ne!(first_token, second_token);
        Ok(())
    }

    fn configuration_happy(interface: String, vid: u16) -> MockConfiguration {
        let mut configuration = MockConfiguration::new();
        configuration.expect_get_app_config().returning(move |_| {
            Ok(AppConfig {
                logical_interface: format!("{}.{}", interface, vid),
                physical_interface: interface.clone(),
                period_ns: Some(0),
                offset_ns: Some(0),
                size_bytes: Some(0),
                destination_address: Some("8b:de:82:a1:59:5a".parse()?),
                vid: Some(vid),
                pcp: Some(4),
                ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 3))),
                prefix_length: Some(16),
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

    fn queue_setup_happy(priority: u8) -> MockQueueSetup {
        let mut queue_setup = MockQueueSetup::new();
        queue_setup.expect_apply_config().returning(move |config| {
            Ok(SocketConfig {
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

    fn guard_happy() -> MockGuard {
        let mut guard = MockGuard::new();
        guard.expect_protect_priority().returning(|_, _, _| Ok(()));
        guard
    }

    fn guard_failing() -> MockGuard {
        let mut guard = MockGuard::new();
        guard
            .expect_protect_priority()
            .returning(|_, _, _| Err(anyhow!("failed")));
        guard
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
        let guard = Arc::new(Mutex::new(guard_happy()));
        let controller = Controller::new();
        let response = controller
            .register("app123", configuration, queue_setup, guard)
            .await?;
        assert_eq!(response.logical_interface, format!("{}.{}", interface, vid));
        assert_eq!(response.priority, priority);
        assert!(response.token > 10); // not GUARANTEED, but VERY unlikely to fail
        Ok(())
    }

    #[tokio::test]
    async fn test_register_configuration_failure() {
        let configuration = Arc::new(Mutex::new(configuration_failing()));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy(32)));
        let guard = Arc::new(Mutex::new(guard_happy()));
        let controller = Controller::new();
        assert!(controller
            .register("app123", configuration, queue_setup, guard)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_register_queue_setup_failure() {
        let configuration = Arc::new(Mutex::new(configuration_happy(String::from("abc"), 4)));
        let queue_setup = Arc::new(Mutex::new(queue_setup_failing()));
        let guard = Arc::new(Mutex::new(guard_happy()));
        let controller = Controller::new();
        assert!(controller
            .register("app123", configuration, queue_setup, guard)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_register_guard_failure() {
        let configuration = Arc::new(Mutex::new(configuration_happy(String::from("abc"), 4)));
        let queue_setup = Arc::new(Mutex::new(queue_setup_happy(32)));
        let guard = Arc::new(Mutex::new(guard_failing()));
        let controller = Controller::new();
        assert!(controller
            .register("app123", configuration, queue_setup, guard)
            .await
            .is_err());
    }
}
