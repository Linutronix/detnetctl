// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Setup the physical and logical network interfaces
#![cfg_attr(not(feature = "netlink"), doc = "```ignore")]
#![cfg_attr(feature = "netlink", doc = "```no_run")]
//! use detnetctl::interface_setup::{InterfaceSetup, NetlinkSetup, LinkState};
//!
//! # tokio_test::block_on(async {
//! let mut interface_setup = NetlinkSetup::new();
//! interface_setup.set_link_state(LinkState::Down, "eth0").await?;
//! interface_setup.add_address("192.168.12.3".parse()?, 32, "eth0").await?;
//! interface_setup.set_link_state(LinkState::Down, "eth0").await?;
//! # Ok::<(), anyhow::Error>(())
//! # });
//! # Ok::<(), anyhow::Error>(())
//! ```

use anyhow::Result;
use async_trait::async_trait;
use std::fmt;
use std::net::IpAddr;

#[cfg(test)]
use mockall::automock;

/// State of a network link
#[derive(Clone, Copy, Debug)]
pub enum LinkState {
    /// Link is active
    Up,

    /// Link is inactive
    Down,
}

impl fmt::Display for LinkState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Up => write!(f, "up"),
            Self::Down => write!(f, "down"),
        }
    }
}

/// Defines how to setup the link
#[cfg_attr(test, automock)]
#[async_trait]
pub trait InterfaceSetup {
    /// Construct a link setup command
    async fn set_link_state(&self, state: LinkState, interface: &str) -> Result<()>;

    /// Add address to interface
    async fn add_address(&self, address: IpAddr, prefix_len: u8, interface: &str) -> Result<()>;

    /// Setup VLAN interface
    async fn setup_vlan_interface(
        &self,
        parent_interface: &str,
        vlan_interface: &str,
        vid: u16,
    ) -> Result<()>;
}

#[cfg(feature = "netlink")]
mod netlink;
#[cfg(feature = "netlink")]
pub use netlink::NetlinkSetup;

/// A link setup doing nothing, but still providing the `InterfaceSetup` trait
///
/// Useful for testing purposes or if you only want to use other features
#[derive(Default)]
pub struct DummyInterfaceSetup;

impl DummyInterfaceSetup {}

#[async_trait]
impl InterfaceSetup for DummyInterfaceSetup {
    async fn set_link_state(&self, _state: LinkState, _interface: &str) -> Result<()> {
        Ok(())
    }

    async fn add_address(&self, _address: IpAddr, _prefix_len: u8, _interface: &str) -> Result<()> {
        Ok(())
    }

    async fn setup_vlan_interface(
        &self,
        _parent_interface: &str,
        _vlan_interface: &str,
        _vid: u16,
    ) -> Result<()> {
        Ok(())
    }
}
