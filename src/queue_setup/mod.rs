// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Setup a TSN-capable NIC and qdiscs
#![cfg_attr(not(feature = "detd"), doc = "```ignore")]
#![cfg_attr(feature = "detd", doc = "```no_run")]
//! use detnetctl::queue_setup::{QueueSetup, DetdGateway};
//! use detnetctl::configuration::AppConfig;
//!
//! let app_config = AppConfig{
//!     logical_interface: String::from("eth0.3"),
//!     physical_interface: String::from("eth0"),
//!     period_ns: Some(1000*100),
//!     offset_ns: Some(0),
//!     size_bytes: Some(1000),
//!     destination_address: Some("8a:de:82:a1:59:5a".parse()?),
//!     vid: Some(3),
//!     pcp: Some(4),
//!     addresses: Some(vec![
//!         ("192.168.3.3".parse()?, 16)
//!     ])
//! };
//! let mut queue_setup = DetdGateway::new(None, None);
//! let socket_config = queue_setup.apply_config(&app_config)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use crate::configuration;
use anyhow::Result;

#[cfg(test)]
use mockall::automock;

/// Configuration returned from the queue setup specifying how to setup the socket
#[derive(Debug)]
pub struct SocketConfig {
    /// Logical interface for the application to bind to (usually a VLAN interface like eth0.2)
    pub logical_interface: String,

    /// Priority that will be routed to the appropriate qdisc
    pub priority: u8,
}

/// Defines how to apply an Ethernet configuration
#[cfg_attr(test, automock)]
pub trait QueueSetup {
    /// Apply the given configuration by setting up NIC and qdiscs
    ///
    /// # Errors
    ///
    /// Will return `Err` if the configuration could not be applied,
    /// e.g. because no connection to `detd` was possible, the
    /// configuration itself is invalid or `detd` is in a state that
    /// does not allow applying this configuration.
    fn apply_config(&self, config: &configuration::AppConfig) -> Result<SocketConfig>;
}

#[cfg(feature = "detd")]
mod detd;
#[cfg(feature = "detd")]
pub use detd::DetdGateway;

/// A queue setup doing nothing, but still providing the `QueueSetup` trait
///
/// Useful for testing purposes (e.g. with NICs without TSN capabilities)
/// or if you only want to use other features without actually configuring the NIC.
pub struct DummyQueueSetup {
    priority: u8,
}

impl DummyQueueSetup {
    /// Create new `DummyQueueSetup`
    ///
    /// # Arguments
    ///
    /// * `priority` - Priority to return from the `apply_config` call
    #[must_use]
    pub const fn new(priority: u8) -> Self {
        Self { priority }
    }
}

impl QueueSetup for DummyQueueSetup {
    fn apply_config(&self, config: &configuration::AppConfig) -> Result<SocketConfig> {
        Ok(SocketConfig {
            logical_interface: config.logical_interface.clone(),
            priority: self.priority,
        })
    }
}
