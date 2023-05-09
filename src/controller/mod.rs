//! Core component of the node controller
//!
//! The controller is combining the configuration, the NIC setup and the guard
//! to perform a complete registration of an application.
//!
//! ```
//! use detnetctl::controller::{Registration, Controller};
//! use detnetctl::configuration::{Configuration, YAMLConfiguration};
//! use detnetctl::nic_setup::{NICSetup, DummyNICSetup};
//! use detnetctl::guard::{Guard, DummyGuard};
//!
//! # #[path = "../configuration/doctest.rs"]
//! # mod doctest;
//! # let tmpfile = doctest::generate_example_yaml();
//! # let filepath = tmpfile.path();
//! use std::fs::File;
//! #
//! let controller = Controller::new();
//! let mut configuration = YAMLConfiguration::new();
//! configuration.read(File::open(filepath)?)?;
//! let mut nic_setup = DummyNICSetup::new(3);
//! let mut guard = DummyGuard::new();
//! let response = controller.register("app0", &mut configuration, &mut nic_setup, &mut guard)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use crate::configuration::Configuration;
use crate::guard::Guard;
use crate::nic_setup::NICSetup;
use anyhow::{Context, Result};
use getrandom::getrandom;

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
pub trait Registration {
    /// Register an application including the following steps
    ///
    /// 1. Generate a random token
    /// 2. Fetch the configuration corresponding to the `app_name`
    /// 3. Set up the NIC according to the configuration
    /// 4. Set up the guard to prevent interfering messages from other applications
    /// 5. Return the appropriate socket settings for the application
    ///
    fn register(
        &self,
        app_name: &str,
        configuration: &mut dyn Configuration,
        nic_setup: &mut dyn NICSetup,
        guard: &mut dyn Guard,
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

impl Registration for Controller {
    fn register(
        &self,
        app_name: &str,
        configuration: &mut dyn Configuration,
        nic_setup: &mut dyn NICSetup,
        guard: &mut dyn Guard,
    ) -> Result<RegisterResponse> {
        println!("Request to register {}", app_name);

        // Generate token
        let token = self.generate_token()?;

        // Fetch configuration for app
        let app_config = configuration
            .get_app_config(app_name)
            .context("Fetching the configuration failed")
            .map_err(|e| {
                // print here and forward, otherwise the error would only be sent back to the application
                eprintln!("{:#}", e);
                e
            })?;
        println!("Fetched from configuration module: {:#?}", app_config);

        // Setup NIC
        let socket_config = nic_setup
            .apply_config(&app_config)
            .context("Setting up the NIC failed")
            .map_err(|e| {
                eprintln!("{:#}", e);
                e
            })?;
        println!("Result of NIC Setup: {:#?}", socket_config);

        // Setup BPF Hooks
        // It is important to use the physical interface (eth0) and not the logical interface (eth0.2)
        // here, because otherwise it would be possible to use a different logical interface,
        // but same SO_PRIORITY and physical interface. Even though it would not be routed to the
        // same VLAN it could still block the time slot!
        guard
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
    use crate::nic_setup::{MockNICSetup, SocketConfig};
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

    fn nic_setup_happy(priority: u8) -> MockNICSetup {
        let mut nic_setup = MockNICSetup::new();
        nic_setup.expect_apply_config().returning(move |config| {
            Ok(SocketConfig {
                logical_interface: config.logical_interface.clone(),
                priority,
            })
        });
        nic_setup
    }

    fn nic_setup_failing() -> MockNICSetup {
        let mut nic_setup = MockNICSetup::new();
        nic_setup
            .expect_apply_config()
            .returning(|_| Err(anyhow!("failed")));
        nic_setup
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

    #[test]
    fn test_register_happy() -> Result<()> {
        let interface = "ethxy";
        let vid = 43;
        let priority = 32;
        let mut configuration = configuration_happy(String::from(interface), vid);
        let mut nic_setup = nic_setup_happy(priority);
        let mut guard = guard_happy();
        let controller = Controller::new();
        let response =
            controller.register("app123", &mut configuration, &mut nic_setup, &mut guard)?;
        assert_eq!(response.logical_interface, format!("{}.{}", interface, vid));
        assert_eq!(response.priority, priority);
        assert!(response.token > 10); // not GUARANTEED, but VERY unlikely to fail
        Ok(())
    }

    #[test]
    fn test_register_configuration_failure() {
        let mut configuration = configuration_failing();
        let mut nic_setup = nic_setup_happy(32);
        let mut guard = guard_happy();
        let controller = Controller::new();
        assert!(controller
            .register("app123", &mut configuration, &mut nic_setup, &mut guard)
            .is_err());
    }

    #[test]
    fn test_register_nic_setup_failure() {
        let mut configuration = configuration_happy(String::from("abc"), 4);
        let mut nic_setup = nic_setup_failing();
        let mut guard = guard_happy();
        let controller = Controller::new();
        assert!(controller
            .register("app123", &mut configuration, &mut nic_setup, &mut guard)
            .is_err());
    }

    #[test]
    fn test_register_guard_failure() {
        let mut configuration = configuration_happy(String::from("abc"), 4);
        let mut nic_setup = nic_setup_happy(32);
        let mut guard = guard_failing();
        let controller = Controller::new();
        assert!(controller
            .register("app123", &mut configuration, &mut nic_setup, &mut guard)
            .is_err());
    }
}
