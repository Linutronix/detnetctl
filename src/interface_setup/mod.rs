// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Setup the physical and logical network interfaces
#![cfg_attr(not(feature = "iproute2"), doc = "```ignore")]
#![cfg_attr(feature = "iproute2", doc = "```no_run")]
//! use detnetctl::interface_setup::{InterfaceSetup, Iproute2Setup, LinkState};
//!
//! # tokio_test::block_on(async {
//! let mut interface_setup = Iproute2Setup::new();
//! interface_setup.set_link_state(LinkState::Down, "eth0", &None).await?;
//! interface_setup.add_ip_address("192.168.12.3".parse()?, 32, "eth0", &None).await?;
//! interface_setup.set_link_state(LinkState::Down, "eth0", &None).await?;
//! # Ok::<(), anyhow::Error>(())
//! # });
//! # Ok::<(), anyhow::Error>(())
//! ```

use anyhow::Result;
use async_trait::async_trait;
use eui48::MacAddress;
use std::fmt;
use std::net::IpAddr;
use std::path::Path;

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
    async fn set_link_state(
        &self,
        state: LinkState,
        interface: &str,
        netns: &Option<String>,
    ) -> Result<()>;

    /// Add IP address to interface
    async fn add_ip_address(
        &self,
        address: IpAddr,
        prefix_len: u8,
        interface: &str,
        netns: &Option<String>,
    ) -> Result<()>;

    /// Set MAC address of interface
    async fn set_mac_address(
        &self,
        address: MacAddress,
        interface: &str,
        netns: &Option<String>,
    ) -> Result<()>;

    /// Setup VLAN interface
    async fn setup_vlan_interface(
        &self,
        parent_interface: &str,
        vlan_interface: &str,
        vid: u16,
    ) -> Result<()>;

    /// Setup VETH pair and move app side to network namespace
    /// Also setup VLAN interfaces if `vlan_ids` are provided.
    /// Corresponding to
    /// `ip netns add netns_app`
    /// `ip link add dev veth_bridge type veth peer name veth_app`
    /// `ip link add link veth_app name veth_app.100 type vlan id 100`
    /// `ip link set dev veth_app netns netns_app`
    /// `ip link set dev veth_app.100 netns netns_app`
    async fn setup_veth_pair_with_vlans(
        &self,
        veth_app: &str,
        netns_app: &str,
        veth_bridge: &str,
        vlan_ids: &[u16],
    ) -> Result<()>;

    /// Set promiscuous mode
    async fn set_promiscuous(
        &self,
        interface: &str,
        enable: bool,
        netns: &Option<String>,
    ) -> Result<()>;

    /// Set VLAN offload
    async fn set_vlan_offload(
        &self,
        interface: &str,
        tx_enable: Option<bool>,
        rx_enable: Option<bool>,
        netns: &Option<String>,
    ) -> Result<()>;

    /// Attach pinned XDP program
    /// This is especially useful when attaching an XDP
    /// program to an interface in a different network namespace
    async fn attach_pinned_xdp(
        &self,
        interface: &str,
        netns: &Option<String>,
        path: &Path,
    ) -> Result<()>;
}

#[cfg(feature = "iproute2")]
mod iproute2;
#[cfg(feature = "iproute2")]
pub use iproute2::Iproute2Setup;

/// A link setup doing nothing, but still providing the `InterfaceSetup` trait
///
/// Useful for testing purposes or if you only want to use other features
#[derive(Default)]
pub struct DummyInterfaceSetup;

impl DummyInterfaceSetup {}

#[async_trait]
impl InterfaceSetup for DummyInterfaceSetup {
    async fn set_link_state(
        &self,
        _state: LinkState,
        _interface: &str,
        _netns: &Option<String>,
    ) -> Result<()> {
        Ok(())
    }

    async fn add_ip_address(
        &self,
        _address: IpAddr,
        _prefix_len: u8,
        _interface: &str,
        _netns: &Option<String>,
    ) -> Result<()> {
        Ok(())
    }

    async fn set_mac_address(
        &self,
        _address: MacAddress,
        _interface: &str,
        _netns: &Option<String>,
    ) -> Result<()> {
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

    async fn setup_veth_pair_with_vlans(
        &self,
        _veth_app: &str,
        _netns_app: &str,
        _veth_bridge: &str,
        _vlan_ids: &[u16],
    ) -> Result<()> {
        Ok(())
    }

    async fn set_promiscuous(
        &self,
        _interface: &str,
        _enable: bool,
        _netns: &Option<String>,
    ) -> Result<()> {
        Ok(())
    }

    async fn set_vlan_offload(
        &self,
        _interface: &str,
        _tx_enable: Option<bool>,
        _rx_enable: Option<bool>,
        _netns: &Option<String>,
    ) -> Result<()> {
        Ok(())
    }

    async fn attach_pinned_xdp(
        &self,
        _interface: &str,
        _netns: &Option<String>,
        _path: &Path,
    ) -> Result<()> {
        Ok(())
    }
}
