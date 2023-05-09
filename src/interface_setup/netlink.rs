use crate::interface_setup::{InterfaceSetup, LinkState};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ethtool;
use ethtool::EthtoolAttr::LinkMode;
use ethtool::EthtoolHandle;
use ethtool::EthtoolLinkModeAttr::Speed;
use futures::stream::TryStreamExt;
use netlink_packet_route::link::nlas::Info::{Data, Kind};
use netlink_packet_route::link::nlas::InfoVlan::{Id, Protocol};
use netlink_packet_route::link::nlas::Nla::Info;
use netlink_packet_route::link::nlas::{InfoData, InfoKind};
use netlink_packet_route::{LinkMessage, IFF_UP};
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
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    async fn get_interface(interface: &str, handle: &Handle) -> Option<LinkMessage> {
        let mut links = handle
            .link()
            .get()
            .match_name(String::from(interface))
            .execute();

        match links.try_next().await {
            Ok(Some(msg)) => Some(msg),
            Err(_) => None,
            Ok(None) => None,
        }
    }

    async fn get_interface_index(interface: &str, handle: &Handle) -> Result<u32> {
        match Self::get_interface(interface, handle).await {
            Some(link) => Ok(link.header.index),
            None => Err(anyhow!("no link {} found", interface)),
        }
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
                    0xFFFFFFFF => Ok(None),
                    _ => Ok(Some(*speed)),
                };
            }
        }

        Err(anyhow!("No ethtool link mode speed message received"))
    }
}

#[async_trait]
impl InterfaceSetup for NetlinkSetup {
    async fn set_link_state(&self, state: LinkState, interface: &str) -> Result<()> {
        {
            let (connection, handle, _) = rtnetlink::new_connection()?;
            tokio::spawn(connection);

            let idx = NetlinkSetup::get_interface_index(interface, &handle).await?;

            let set_request = handle.link().set(idx);
            match state {
                LinkState::UP => set_request.up(),
                LinkState::DOWN => set_request.down(),
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

        let idx = NetlinkSetup::get_interface_index(interface, &handle).await?;

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
            return validate_link(link, vlan_interface, vid);
        }

        let parent_idx = NetlinkSetup::get_interface_index(parent_interface, &handle).await?;

        let mut request = handle
            .link()
            .add()
            .vlan(vlan_interface.into(), parent_idx, vid);
        // We want to set the interface state to up manually later
        request.message_mut().header.flags &= !IFF_UP;
        request.message_mut().header.change_mask &= !IFF_UP;
        Ok(request.execute().await?)
    }
}

fn validate_link(link: LinkMessage, vlan_interface: &str, vid: u16) -> Result<()> {
    // VLAN interface already exists
    // Validate that configuration is compatible
    let info = link
        .nlas
        .iter()
        .find_map(|d| match d {
            Info(info) => Some(info),
            _ => None,
        })
        .ok_or_else(|| anyhow!("No link info found for {}", vlan_interface))?;

    // Validate info kind
    let kind = info.iter().find_map(|d| match d {
        Kind(kind) => Some(kind),
        _ => None,
    });
    if kind.is_none() || *kind.unwrap() != InfoKind::Vlan {
        return Err(anyhow!("Data kind invalid for {}", vlan_interface));
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
    if protocol.is_none() || *protocol.unwrap() != ETH_P_8021Q {
        return Err(anyhow!(
            "VLAN protocol for {} is not 0x{:x}",
            vlan_interface,
            ETH_P_8021Q
        ));
    }

    // Validate VLAN ID
    let vlan_id = data.iter().find_map(|d| match d {
        Id(vlan_id) => Some(vlan_id),
        _ => None,
    });
    if vlan_id.is_none() || *vlan_id.unwrap() != vid {
        return Err(anyhow!("VLAN ID for {} is not {}", vlan_interface, vid));
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
        validate_link(link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "Data kind invalid for eth0.5")]
    fn test_link_no_kind() {
        let mut link = LinkMessage::default();
        link.nlas.push(Info(vec![]));
        validate_link(link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "Data kind invalid for eth0.5")]
    fn test_link_invalid_kind() {
        let mut link = LinkMessage::default();
        link.nlas.push(Info(vec![Kind(InfoKind::Bridge)]));
        validate_link(link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "No VLAN info data found for eth0.5")]
    fn test_link_missing_data() {
        let mut link = LinkMessage::default();
        link.nlas.push(Info(vec![Kind(InfoKind::Vlan)]));
        validate_link(link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "No VLAN info data found for eth0.5")]
    fn test_link_wrong_data() {
        let mut link = LinkMessage::default();
        link.nlas.push(Info(vec![
            Kind(InfoKind::Vlan),
            Data(InfoData::Bridge(vec![])),
        ]));
        validate_link(link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "VLAN protocol for eth0.5 is not 0x8100")]
    fn test_link_missing_protocol() {
        let mut link = LinkMessage::default();
        link.nlas.push(Info(vec![
            Kind(InfoKind::Vlan),
            Data(InfoData::Vlan(vec![])),
        ]));
        validate_link(link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "VLAN protocol for eth0.5 is not 0x8100")]
    fn test_link_wrong_protocol() {
        let mut link = LinkMessage::default();
        link.nlas.push(Info(vec![
            Kind(InfoKind::Vlan),
            Data(InfoData::Vlan(vec![Protocol(0x8102)])),
        ]));
        validate_link(link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "VLAN ID for eth0.5 is not 5")]
    fn test_link_missing_vid() {
        let mut link = LinkMessage::default();
        link.nlas.push(Info(vec![
            Kind(InfoKind::Vlan),
            Data(InfoData::Vlan(vec![Protocol(0x8100)])),
        ]));
        validate_link(link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "VLAN ID for eth0.5 is not 5")]
    fn test_link_wrong_vid() {
        let mut link = LinkMessage::default();
        link.nlas.push(Info(vec![
            Kind(InfoKind::Vlan),
            Data(InfoData::Vlan(vec![Protocol(0x8100), Id(8)])),
        ]));
        validate_link(link, VLAN_INTERFACE, VID).unwrap();
    }

    #[test]
    fn test_link_valid() {
        let mut link = LinkMessage::default();
        link.nlas.push(Info(vec![
            Kind(InfoKind::Vlan),
            Data(InfoData::Vlan(vec![Protocol(0x8100), Id(5)])),
        ]));
        validate_link(link, VLAN_INTERFACE, VID).unwrap();
    }
}
