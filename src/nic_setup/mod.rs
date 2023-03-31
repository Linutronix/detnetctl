//! Setup a TSN-capable NIC and qdiscs
//!
//! ```no_run
//! use detnetctl::nic_setup::{NICSetup, DetdGateway};
//! use detnetctl::configuration::EthernetConfig;
//!
//! let ethernet_config = EthernetConfig{
//!     logical_interface: String::from("eth0.3"),
//!     physical_interface: String::from("eth0"),
//!     period_ns: Some(1000*100),
//!     offset_ns: Some(0),
//!     size_bytes: Some(1000),
//!     destination_address: Some("8a:de:82:a1:59:5a".parse()?),
//!     vid: Some(3),
//!     pcp: Some(4),
//! };
//! let mut nic_setup = DetdGateway::new(None, None)?;
//! let socket_config = nic_setup.apply_config(&ethernet_config)?;
//! # Ok::<(), anyhow::Error>(())
//! ```
use crate::configuration;
use anyhow::Result;

#[cfg(test)]
use mockall::automock;

/// Configuration returned from the NIC setup specifying how to setup the socket
#[derive(Debug)]
pub struct SocketConfig {
    /// Logical interface for the application to bind to (usually a VLAN interface like eth0.2)
    pub logical_interface: String,

    /// Priority that will be routed to the appropriate qdisc
    pub priority: u8,
}

/// Defines how to apply an Ethernet configuration
#[cfg_attr(test, automock)]
pub trait NICSetup {
    /// Apply the given configuration by setting up NIC and qdiscs
    fn apply_config(&self, config: &configuration::EthernetConfig) -> Result<SocketConfig>;
}

#[cfg(feature = "detd")]
mod detd;
#[cfg(feature = "detd")]
pub use detd::DetdGateway;

/// A NIC setup doing nothing, but still providing the NICSetup trait
///
/// Useful for testing purposes (e.g. with NICs without TSN capabilities)
/// or if you only want to use other features without actually installing configuring the NIC.
pub struct DummyNICSetup {
    priority: u8,
}

impl DummyNICSetup {
    /// Create new DummyNICSetup
    ///
    /// # Arguments
    ///
    /// * `priority` - Priority to return from the apply_config call
    pub fn new(priority: u8) -> Self {
        DummyNICSetup { priority }
    }
}

impl NICSetup for DummyNICSetup {
    fn apply_config(&self, config: &configuration::EthernetConfig) -> Result<SocketConfig> {
        Ok(SocketConfig {
            logical_interface: config.logical_interface.clone(),
            priority: self.priority,
        })
    }
}
