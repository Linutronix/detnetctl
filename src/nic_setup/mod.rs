//! Setup a TSN-capable NIC and qdiscs
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
