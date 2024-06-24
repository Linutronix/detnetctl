// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::interface_setup::{InterfaceSetup, LinkState};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ethtool;
use ethtool::EthtoolAttr::LinkMode;
use ethtool::EthtoolHandle;
use ethtool::EthtoolLinkModeAttr::Speed;
use futures::stream::TryStreamExt;
use netlink_packet_route::link::InfoVlan::{Id, Protocol};
use netlink_packet_route::link::LinkAttribute::LinkInfo;
use netlink_packet_route::link::LinkInfo::{Data, Kind};
use netlink_packet_route::link::{InfoData, InfoKind};
use netlink_packet_route::link::{LinkFlag, LinkMessage, VlanProtocol};
use rtnetlink::Handle;
use std::net::IpAddr;
use tokio::time::{sleep, Duration, Instant};

const INTERFACE_STATE_CHANGE_TIMEOUT: Duration = Duration::from_secs(10);
const INTERFACE_STATE_CHANGE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const ETH_P_8021Q: u16 = 0x8100;

/// Setup interface via netlink
pub struct NetlinkSetup;

impl NetlinkSetup {
    /// Create new netlink setup
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    async fn get_interface(interface: &str, handle: &Handle) -> Option<LinkMessage> {
        let mut links = handle
            .link()
            .get()
            .match_name(String::from(interface))
            .execute();

        match links.try_next().await {
            Ok(Some(msg)) => Some(msg),
            Err(_) | Ok(None) => None,
        }
    }

    /// Get the index for the given interface name
    pub async fn get_interface_index(interface: &str, handle: &Handle) -> Option<u32> {
        Self::get_interface(interface, handle)
            .await
            .map(|link| link.header.index)
    }

    async fn get_interface_speed(
        &self,
        interface: &str,
        handle: &mut EthtoolHandle,
    ) -> Result<Option<u32>> {
        let mut link_mode_handle = handle.link_mode().get(Some(interface)).execute().await;

        while let Some(msg) = link_mode_handle.try_next().await? {
            let speed = msg.payload.nlas.iter().find_map(|d| match d {
                LinkMode(Speed(speed)) => Some(speed),
                _ => None,
            });

            if let Some(speed) = speed {
                return match speed {
                    0xFFFF_FFFF => Ok(None),
                    _ => Ok(Some(*speed)),
                };
            }
        }

        Err(anyhow!("No ethtool link mode speed message received"))
    }
}

impl Default for NetlinkSetup {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl InterfaceSetup for NetlinkSetup {
    async fn set_link_state(&self, state: LinkState, interface: &str) -> Result<()> {
        {
            let (connection, handle, _) = rtnetlink::new_connection()?;
            tokio::spawn(connection);

            let idx = Self::get_interface_index(interface, &handle)
                .await
                .ok_or_else(|| anyhow!("No interface {interface} found"))?;

            let set_request = handle.link().set(idx);
            match state {
                LinkState::Up => set_request.up(),
                LinkState::Down => set_request.down(),
            }
            .execute()
            .await?;
        }

        // Directly after setting the link state, it takes some time until
        // it is properly applied. E.g. the speed of the link mode is not yet
        // known. Therefore, poll it until the state was properly applied.
        let start_time = Instant::now();
        let (ethtool_connection, mut ethtool_handle, _) = ethtool::new_connection()?;
        tokio::spawn(ethtool_connection);
        loop {
            let speed = self
                .get_interface_speed(interface, &mut ethtool_handle)
                .await?;
            if speed.is_some() {
                return Ok(());
            }

            if start_time.elapsed() >= INTERFACE_STATE_CHANGE_TIMEOUT {
                return Err(anyhow!(
                    "Timeout reading interface speed after setting state"
                ));
            }

            sleep(INTERFACE_STATE_CHANGE_POLL_INTERVAL).await;
        }
    }

    async fn add_address(&self, address: IpAddr, prefix_len: u8, interface: &str) -> Result<()> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        let idx = Self::get_interface_index(interface, &handle)
            .await
            .ok_or_else(|| anyhow!("No interface {interface} found"))?;

        handle
            .address()
            .add(idx, address, prefix_len)
            .replace()
            .execute()
            .await?;

        Ok(())
    }

    async fn setup_vlan_interface(
        &self,
        parent_interface: &str,
        vlan_interface: &str,
        vid: u16,
    ) -> Result<()> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        if let Some(link) = Self::get_interface(vlan_interface, &handle).await {
            // no need to add the interface, but still validate if it matches
            return validate_link(&link, vlan_interface, vid);
        }

        let parent_idx = Self::get_interface_index(parent_interface, &handle)
            .await
            .ok_or_else(|| anyhow!("No parent interface {parent_interface} found"))?;

        let mut request = handle
            .link()
            .add()
            .vlan(vlan_interface.into(), parent_idx, vid);
        // We want to set the interface state to up manually later
        request
            .message_mut()
            .header
            .flags
            .retain(|&x| x != LinkFlag::Up);
        request
            .message_mut()
            .header
            .change_mask
            .retain(|&x| x != LinkFlag::Up);
        Ok(request.execute().await?)
    }
}

fn validate_link(link: &LinkMessage, vlan_interface: &str, vid: u16) -> Result<()> {
    // VLAN interface already exists
    // Validate that configuration is compatible
    let info = link
        .attributes
        .iter()
        .find_map(|d| match d {
            LinkInfo(info) => Some(info),
            _ => None,
        })
        .ok_or_else(|| anyhow!("No link info found for {}", vlan_interface))?;

    // Validate info kind
    let kind = info.iter().find_map(|d| match d {
        Kind(kind) => Some(kind),
        _ => None,
    });
    match kind {
        Some(k) if k == &InfoKind::Vlan => (),
        _ => return Err(anyhow!("Data kind invalid for {}", vlan_interface)),
    }

    // Extract data
    let data = info
        .iter()
        .find_map(|d| match d {
            Data(InfoData::Vlan(vlan)) => Some(vlan),
            _ => None,
        })
        .ok_or_else(|| anyhow!("No VLAN info data found for {}", vlan_interface))?;

    // Validate protocol
    let protocol = data.iter().find_map(|d| match d {
        Protocol(protocol) => Some(protocol),
        _ => None,
    });
    match protocol {
        Some(p) if p == &VlanProtocol::Ieee8021Q => (),
        _ => {
            return Err(anyhow!(
                "VLAN protocol for {} is not 0x{:x}",
                vlan_interface,
                ETH_P_8021Q
            ))
        }
    }

    // Validate VLAN ID
    let vlan_id = data.iter().find_map(|d| match d {
        Id(vlan_id) => Some(vlan_id),
        _ => None,
    });
    match vlan_id {
        Some(id) if id == &vid => (),
        _ => return Err(anyhow!("VLAN ID for {} is not {}", vlan_interface, vid)),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VLAN_INTERFACE: &str = "eth0.5";
    const VID: u16 = 5;

    #[test]
    #[should_panic(expected = "No link info found for eth0.5")]
    fn test_link_empty() {
        let link = LinkMessage::default();
        validate_link(&link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "Data kind invalid for eth0.5")]
    fn test_link_no_kind() {
        let mut link = LinkMessage::default();
        link.attributes.push(LinkInfo(vec![]));
        validate_link(&link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "Data kind invalid for eth0.5")]
    fn test_link_invalid_kind() {
        let mut link = LinkMessage::default();
        link.attributes.push(LinkInfo(vec![Kind(InfoKind::Bridge)]));
        validate_link(&link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "No VLAN info data found for eth0.5")]
    fn test_link_missing_data() {
        let mut link = LinkMessage::default();
        link.attributes.push(LinkInfo(vec![Kind(InfoKind::Vlan)]));
        validate_link(&link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "No VLAN info data found for eth0.5")]
    fn test_link_wrong_data() {
        let mut link = LinkMessage::default();
        link.attributes.push(LinkInfo(vec![
            Kind(InfoKind::Vlan),
            Data(InfoData::Bridge(vec![])),
        ]));
        validate_link(&link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "VLAN protocol for eth0.5 is not 0x8100")]
    fn test_link_missing_protocol() {
        let mut link = LinkMessage::default();
        link.attributes.push(LinkInfo(vec![
            Kind(InfoKind::Vlan),
            Data(InfoData::Vlan(vec![])),
        ]));
        validate_link(&link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "VLAN protocol for eth0.5 is not 0x8100")]
    fn test_link_wrong_protocol() {
        let mut link = LinkMessage::default();
        link.attributes.push(LinkInfo(vec![
            Kind(InfoKind::Vlan),
            Data(InfoData::Vlan(vec![Protocol(0x88A8.into())])),
        ]));
        validate_link(&link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "VLAN ID for eth0.5 is not 5")]
    fn test_link_missing_vid() {
        let mut link = LinkMessage::default();
        link.attributes.push(LinkInfo(vec![
            Kind(InfoKind::Vlan),
            Data(InfoData::Vlan(vec![Protocol(0x8100.into())])),
        ]));
        validate_link(&link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "VLAN ID for eth0.5 is not 5")]
    fn test_link_wrong_vid() {
        let mut link = LinkMessage::default();
        link.attributes.push(LinkInfo(vec![
            Kind(InfoKind::Vlan),
            Data(InfoData::Vlan(vec![Protocol(0x8100.into()), Id(8)])),
        ]));
        validate_link(&link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    fn test_link_valid() {
        let mut link = LinkMessage::default();
        link.attributes.push(LinkInfo(vec![
            Kind(InfoKind::Vlan),
            Data(InfoData::Vlan(vec![Protocol(0x8100.into()), Id(5)])),
        ]));
        validate_link(&link, VLAN_INTERFACE, VID).unwrap();
    }
}
