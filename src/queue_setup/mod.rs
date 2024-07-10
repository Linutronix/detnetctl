// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Setup a TSN-capable NIC and qdiscs
#![cfg_attr(not(feature = "detd"), doc = "```ignore")]
#![cfg_attr(feature = "detd", doc = "```no_run")]
//! use detnetctl::queue_setup::{QueueSetup, DetdGateway};
//! use detnetctl::configuration::{AppConfigBuilder, StreamIdentificationBuilder};
//!
//! let app_config = AppConfigBuilder::new()
//!     .logical_interface("eth0.3".to_owned())
//!     .physical_interface("eth0".to_owned())
//!     .period_ns(1000*100)
//!     .offset_ns(0)
//!     .size_bytes(1000)
//!     .stream(
//!         StreamIdentificationBuilder::new()
//!         .destination_address("8a:de:82:a1:59:5a".parse()?)
//!         .vid(3)
//!         .build()
//!     )
//!     .pcp(4)
//!     .addresses(vec![
//!         ("192.168.3.3".parse()?, 16)
//!     ])
//!     .build();
//!
//! let mut queue_setup = DetdGateway::new(None, None);
//! let response = queue_setup.apply_config(&app_config)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use crate::configuration::Interface;
use anyhow::Result;
use async_trait::async_trait;

#[cfg(test)]
use mockall::automock;

#[cfg(feature = "netlink")]
mod taprio;
#[cfg(feature = "netlink")]
pub use taprio::TaprioSetup;

/// Defines how to apply an Ethernet configuration
#[cfg_attr(test, automock)]
#[async_trait]
pub trait QueueSetup {
    /// Apply the given configuration by setting up NIC and qdiscs
    ///
    /// # Errors
    ///
    /// Will return `Err` if the configuration could not be applied,
    /// e.g. because the configuration itself is invalid or the system
    /// is in a state that does not allow applying this configuration.
    async fn apply_config(&self, interface_name: &str, interface_config: &Interface) -> Result<()>;
}

/// A queue setup doing nothing, but still providing the `QueueSetup` trait
///
/// Useful for testing purposes (e.g. with NICs without TSN capabilities)
/// or if you only want to use other features without actually configuring the NIC.
pub struct DummyQueueSetup;

#[async_trait]
impl QueueSetup for DummyQueueSetup {
    async fn apply_config(
        &self,
        _interface_name: &str,
        _interface_config: &Interface,
    ) -> Result<()> {
        Ok(())
    }
}
