// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::interface_setup::{InterfaceSetup, LinkState};
use anyhow::{anyhow, ensure, Context, Result};
use async_trait::async_trait;
use eui48::MacAddress;
use serde_json::Value;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use tokio::process::Command;
use tokio::time::{sleep, Duration, Instant};

const INTERFACE_STATE_CHANGE_TIMEOUT: Duration = Duration::from_secs(20);
const INTERFACE_STATE_CHANGE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const NETNS_PATH: &str = "/run/netns/";

/// Setup interface via netlink
pub struct Iproute2Setup;

impl Iproute2Setup {
    /// Create new netlink setup
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    async fn execute_ip(args: &[&str], netns: &Option<String>) -> Result<Value> {
        let mut cmd = netns.as_ref().map_or_else(
            || Command::new("ip"),
            |namespace| {
                let mut nscmd = Command::new("nsenter");
                nscmd.arg(format!("--net=/run/netns/{namespace}")).arg("ip");
                nscmd
            },
        );

        cmd.arg("-json").args(args);

        let output = cmd
            .output()
            .await
            .with_context(|| format!("Failed to execute command {:?}", cmd.as_std()))?;

        if !output.status.success() {
            let stderr = String::from_utf8(output.stderr).with_context(|| {
                format!(
                    "Invalid UTF-8 sequence returned when executing\n{:?}",
                    cmd.as_std()
                )
            })?;

            return Err(anyhow!(
                "Command\n{:?}\nfailed with status: {}, {}",
                cmd.as_std(),
                output.status,
                stderr
            ));
        }

        let stdout = String::from_utf8(output.stdout).with_context(|| {
            format!(
                "Invalid UTF-8 sequence returned when executing\n{:?}",
                cmd.as_std()
            )
        })?;

        if stdout.trim().is_empty() {
            return Ok(Value::Null);
        }

        let result = serde_json::from_str::<Value>(&stdout)
            .with_context(|| format!("Failed to parse JSON of {:?}", cmd.as_std()))?;

        let values: &Vec<Value> = result
            .as_array()
            .ok_or_else(|| anyhow!("No JSON array returned for {:?}", cmd.as_std()))?;

        ensure!(values.len() == 1, "No unique result for {:?}", cmd.as_std());

        values
            .first()
            .ok_or_else(|| anyhow!("No element found"))
            .cloned()
    }

    async fn execute_ethtool(args: &[&str], netns: &Option<String>) -> Result<String> {
        let mut cmd = netns.as_ref().map_or_else(
            || {
                let mut ethtoolcmd = Command::new("ethtool");
                ethtoolcmd.args(args);
                ethtoolcmd
            },
            |namespace| {
                let mut ipcmd = Command::new("ip");
                ipcmd
                    .arg("netns")
                    .arg("exec")
                    .arg(namespace)
                    .arg("ethtool")
                    .args(args);
                ipcmd
            },
        );

        let output = cmd.output().await?;

        let stdout = String::from_utf8(output.stdout).context("Invalid UTF-8 sequence")?;

        if !output.status.success() {
            return Err(anyhow!(
                "Command failed with status: {}, {}",
                output.status,
                stdout
            ));
        }

        Ok(stdout)
    }

    async fn get_interface(interface: &str, netns: &Option<String>) -> Result<Option<Value>> {
        match Self::execute_ip(&["-detail", "link", "show", interface], netns).await {
            Err(e) => {
                if e.to_string()
                    .contains(&format!("Device \"{interface}\" does not exist."))
                {
                    return Ok(None);
                }

                Err(e)
            }
            Ok(j) => Ok(Some(j)),
        }
    }

    /// Get the index for the given interface name
    ///
    /// # Errors
    /// If an interface was found, but the interface index could not be determined.
    pub async fn get_interface_index(
        interface: &str,
        netns: &Option<String>,
    ) -> Result<Option<u32>> {
        Self::get_interface(interface, netns).await.map(|r| {
            r.map(|j| -> Result<u32> {
                Ok(j.get("ifindex")
                    .ok_or_else(|| anyhow!("ifindex missing"))?
                    .as_i64()
                    .ok_or_else(|| anyhow!("ifindex not an integer"))?
                    .try_into()?)
            })
            .transpose()
        })?
    }

    async fn get_interface_speed(
        &self,
        interface: &str,
        netns: &Option<String>,
    ) -> Result<Option<u32>> {
        let stdout = Self::execute_ethtool(&[interface], netns).await?;

        for line in stdout.lines() {
            if line.trim().starts_with("Speed:") {
                let parts: Vec<&str> = line.split_whitespace().collect();

                let speed = parts
                    .get(1)
                    .ok_or_else(|| anyhow!("failed to parse speed"))?;

                if speed.ends_with("Mb/s") {
                    let speed_value = speed.replace("Mb/s", "");
                    return Ok(Some(speed_value.parse()?));
                }

                return Ok(None);
            }
        }

        Err(anyhow!("No speed entry found"))
    }

    async fn move_to_namespace(netns: &str, interface: &str) -> Result<()> {
        Self::execute_ip(&["link", "set", "dev", interface, "netns", netns], &None).await?;
        Ok(())
    }
}

impl Default for Iproute2Setup {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl InterfaceSetup for Iproute2Setup {
    async fn set_link_state(
        &self,
        state: LinkState,
        interface: &str,
        netns: &Option<String>,
    ) -> Result<()> {
        let state_cmd = match state {
            LinkState::Up => "up",
            LinkState::Down => "down",
        };

        Self::execute_ip(&["link", "set", state_cmd, "dev", interface], netns).await?;

        if state == LinkState::Down {
            // For setting the link down, it is not
            // important to wait. Also, requesting
            // the link speed for a link that is down
            // is not an adequate method. So just skip it.
            return Ok(());
        }

        // Directly after setting the link state, it takes some time until
        // it is properly applied. E.g. the speed of the link mode is not yet
        // known. Therefore, poll it until the state was properly applied.
        let start_time = Instant::now();
        loop {
            let speed = self.get_interface_speed(interface, netns).await?;
            if speed.is_some() {
                return Ok(());
            }

            if start_time.elapsed() >= INTERFACE_STATE_CHANGE_TIMEOUT {
                return Ok(());
                /*
                return Err(anyhow!(
                    "Timeout reading interface speed after setting state"
                ));
                */
            }

            sleep(INTERFACE_STATE_CHANGE_POLL_INTERVAL).await;
        }
    }

    async fn add_ip_address(
        &self,
        address: IpAddr,
        prefix_len: u8,
        interface: &str,
        netns: &Option<String>,
    ) -> Result<()> {
        match Self::execute_ip(
            &[
                "address",
                "add",
                &format!("{address}/{prefix_len}"),
                "dev",
                interface,
            ],
            netns,
        )
        .await
        {
            Err(e) => {
                if e.to_string().contains("already assigned") {
                    return Ok(());
                }

                Err(e)
            }
            Ok(_j) => Ok(()),
        }
    }

    async fn get_ip_addresses(
        &self,
        interface: &str,
        netns: &Option<String>,
    ) -> Result<Vec<IpAddr>> {
        let iface = Self::execute_ip(&["-detail", "address", "show", interface], netns).await?;

        iface
            .get("addr_info")
            .ok_or_else(|| anyhow!("addr_info not found for {interface}"))?
            .as_array()
            .ok_or_else(|| anyhow!("addr_info not an array for {interface}"))?
            .iter()
            .map(|addr| -> Result<IpAddr> {
                Ok(addr
                    .get("local")
                    .ok_or_else(|| anyhow!("no local entry for address for {interface}"))?
                    .as_str()
                    .ok_or_else(|| anyhow!("local entry for address not a string for {interface}"))?
                    .parse()?)
            })
            .collect::<Result<Vec<IpAddr>>>()
    }

    async fn set_mac_address(
        &self,
        address: MacAddress,
        interface: &str,
        netns: &Option<String>,
    ) -> Result<()> {
        Self::execute_ip(
            &[
                "link",
                "set",
                "dev",
                interface,
                "address",
                &address.to_hex_string(),
            ],
            netns,
        )
        .await?;

        Ok(())
    }

    async fn get_mac_address(&self, interface: &str, netns: &Option<String>) -> Result<MacAddress> {
        let iface = Self::get_interface(interface, netns)
            .await?
            .ok_or_else(|| anyhow!("Interface {interface} not found"))?;

        Ok(MacAddress::parse_str(
            iface
                .get("address")
                .ok_or_else(|| anyhow!("No address found for {interface}"))?
                .as_str()
                .ok_or_else(|| anyhow!("Address of {interface} not a string"))?,
        )?)
    }

    async fn setup_vlan_interface(
        &self,
        parent_interface: &str,
        vlan_interface: &str,
        vid: u16,
    ) -> Result<()> {
        if let Some(link) = Self::get_interface(vlan_interface, &None).await? {
            // no need to add the interface, but still validate if it matches
            if parent_interface == vlan_interface {
                return Ok(());
            } else {
                return validate_vlan_link(&link, vlan_interface, parent_interface, vid);
            }
        }

        Self::execute_ip(
            &[
                "link",
                "add",
                "link",
                parent_interface,
                "name",
                vlan_interface,
                "type",
                "vlan",
                "id",
                &vid.to_string(),
            ],
            &None,
        )
        .await?;

        // We want to set the interface state to up manually later
        self.set_link_state(LinkState::Down, vlan_interface, &None)
            .await
    }

    async fn setup_veth_pair_with_vlans(
        &self,
        veth_app: &str,
        netns_app: Option<&String>,
        veth_bridge: &str,
        vlan_ids: &[u16],
    ) -> Result<()> {
        if let Some(veth_link) = Self::get_interface(veth_bridge, &None).await? {
            // no need to add the interfaces, but still validate if they match
            return validate_veth_link(&veth_link, veth_app, netns_app, vlan_ids).await;
        }

        // Setup network namespace if it does not exist
        if let Some(netns) = netns_app {
            let ns_path = namespace_path(netns);
            if !ns_path.exists() {
                Self::execute_ip(&["netns", "add", netns], &None).await?;
            }
        }

        // Create veth pair
        Self::execute_ip(
            &[
                "link",
                "add",
                "dev",
                veth_bridge,
                "type",
                "veth",
                "peer",
                "name",
                veth_app,
            ],
            &None,
        )
        .await?;

        for vid in vlan_ids {
            let vlan_interface = &format!("{veth_app}.{vid}");
            self.setup_vlan_interface(veth_app, vlan_interface, *vid)
                .await?;

            if let Some(netns) = netns_app {
                Self::move_to_namespace(netns, vlan_interface).await?;
            }
        }

        if let Some(netns) = netns_app {
            Self::move_to_namespace(netns, veth_app).await?;
        }

        Ok(())
    }

    async fn set_promiscuous(
        &self,
        interface: &str,
        enable: bool,
        netns: &Option<String>,
    ) -> Result<()> {
        let state_cmd = if enable { "on" } else { "off" };

        Self::execute_ip(&["link", "set", interface, "promisc", state_cmd], netns).await?;

        Ok(())
    }

    async fn set_vlan_offload(
        &self,
        interface: &str,
        tx_enable: Option<bool>,
        rx_enable: Option<bool>,
        netns: &Option<String>,
    ) -> Result<()> {
        if let Some(tx) = tx_enable {
            Self::execute_ethtool(
                &[
                    "-K",
                    interface,
                    "tx-vlan-offload",
                    if tx { "on" } else { "off" },
                ],
                netns,
            )
            .await
            .with_context(|| format!("Setting tx-vlan-offload for {interface} failed"))?;
        }

        if let Some(rx) = rx_enable {
            Self::execute_ethtool(
                &[
                    "-K",
                    interface,
                    "rx-vlan-offload",
                    if rx { "on" } else { "off" },
                ],
                netns,
            )
            .await
            .with_context(|| format!("Setting rx-vlan-offload for {interface} failed"))?;
        }

        Ok(())
    }

    async fn attach_pinned_xdp(
        &self,
        interface: &str,
        netns: &Option<String>,
        path: &Path,
    ) -> Result<()> {
        Self::execute_ip(
            &[
                // do not set XDP_FLAGS_UPDATE_IF_NOEXIST in line
                // with how the direct BPF attach is implemented
                "-force",
                "link",
                "set",
                "dev",
                interface,
                "xdp",
                "pinned",
                path.to_str()
                    .ok_or_else(|| anyhow!("Failed to convert path"))?,
            ],
            netns,
        )
        .await?;

        Ok(())
    }
}

fn namespace_path(name: &str) -> PathBuf {
    let mut netns_path = PathBuf::new();
    netns_path.push(NETNS_PATH);
    netns_path.push(name);
    netns_path
}

fn validate_vlan_link(
    link: &Value,
    vlan_interface: &str,
    parent_interface: &str,
    vid: u16,
) -> Result<()> {
    ensure!(
        link.get("linkinfo")
            .is_some_and(|x| x.get("info_kind").is_some_and(|y| y == "vlan")),
        "{vlan_interface} is not a valid VLAN interface"
    );
    ensure!(
        link.get("link").is_some_and(|x| x == parent_interface),
        "no or wrong parent interface found for {vlan_interface}"
    );
    ensure!(
        link.get("linkinfo").is_some_and(|x| x
            .get("info_data")
            .is_some_and(|y| y.get("protocol").is_some_and(|z| z == "802.1Q"))),
        "wrong VLAN protocol for {vlan_interface}"
    );
    ensure!(
        link.get("linkinfo").is_some_and(|x| x
            .get("info_data")
            .is_some_and(|y| y.get("id").is_some_and(|z| z == vid))),
        "VLAN ID for {vlan_interface} is not {vid}"
    );

    Ok(())
}

async fn validate_veth_link(
    veth_bridge_link: &Value,
    veth_app: &str,
    netns_app: Option<&String>,
    vlan_ids: &[u16],
) -> Result<()> {
    for vid in vlan_ids {
        let vlan_interface = &format!("{veth_app}.{vid}");
        //let vlan_link = Iproute2Setup::get_interface(vlan_interface, &Some(netns_app.to_owned()))
        let vlan_link = Iproute2Setup::get_interface(vlan_interface, &netns_app.cloned())
            .await?
            .ok_or_else(|| anyhow!("interface {vlan_interface} not found"))?;

        validate_vlan_link(&vlan_link, vlan_interface, veth_app, *vid)?;
    }

    //let veth_app_link = Iproute2Setup::get_interface(veth_app, &Some(netns_app.to_owned()))
    let veth_app_link = Iproute2Setup::get_interface(veth_app, &netns_app.cloned())
        .await?
        .ok_or_else(|| anyhow!("interface not found"))?;

    let veth_bridge_index = veth_bridge_link
        .get("ifindex")
        .ok_or_else(|| anyhow!("ifindex not found"))?;
    ensure!(
        veth_app_link
            .get("link_index")
            .is_some_and(|x| x == veth_bridge_index),
        "link index for veth pair does not match"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VLAN_INTERFACE: &str = "eth0.5";
    const PARENT_INTERFACE: &str = "eth0";
    const VID: u16 = 5;

    const LINK: &str = r#"{
          "ifindex":19,
          "link":"eth0",
          "ifname":"eth0.5",
          "flags":[
             "BROADCAST",
             "MULTICAST"
          ],
          "mtu":1500,
          "qdisc":"noop",
          "operstate":"DOWN",
          "linkmode":"DEFAULT",
          "group":"default",
          "txqlen":1000,
          "link_type":"ether",
          "address":"54:44:a3:2b:41:c5",
          "broadcast":"ff:ff:ff:ff:ff:ff",
          "promiscuity":0,
          "allmulti":0,
          "min_mtu":0,
          "max_mtu":65535,
          "linkinfo":{
             "info_kind":"vlan",
             "info_data":{
                "protocol":"802.1Q",
                "id":5,
                "flags":[
                   "REORDER_HDR"
                ]
             }
          },
          "inet6_addr_gen_mode":"eui64",
          "num_tx_queues":1,
          "num_rx_queues":1,
          "gso_max_size":16354,
          "gso_max_segs":65535,
          "tso_max_size":16354,
          "tso_max_segs":65535,
          "gro_max_size":65536
       }"#;

    #[test]
    #[should_panic(expected = "eth0.5 is not a valid VLAN interface")]
    fn test_link_empty() {
        let link = Value::default();
        validate_vlan_link(&link, VLAN_INTERFACE, PARENT_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "no or wrong parent interface found for eth0.5")]
    fn test_link_wrong_parent() {
        let mut link: Value = serde_json::from_str(LINK).unwrap();
        link["link"] = "foo".into();
        validate_vlan_link(&link, VLAN_INTERFACE, PARENT_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "wrong VLAN protocol for eth0.5")]
    fn test_link_wrong_protocol() {
        let mut link: Value = serde_json::from_str(LINK).unwrap();
        link["linkinfo"]["info_data"]["protocol"] = "foo".into();
        validate_vlan_link(&link, VLAN_INTERFACE, PARENT_INTERFACE, VID).unwrap();
    }

    #[test]
    #[should_panic(expected = "VLAN ID for eth0.5 is not 5")]
    fn test_link_wrong_vid() {
        let mut link: Value = serde_json::from_str(LINK).unwrap();
        link["linkinfo"]["info_data"]["id"] = 15.into();
        validate_vlan_link(&link, VLAN_INTERFACE, PARENT_INTERFACE, VID).unwrap();
    }

    #[test]
    fn test_link_valid() {
        let link = serde_json::from_str(LINK).unwrap();
        validate_vlan_link(&link, VLAN_INTERFACE, PARENT_INTERFACE, VID).unwrap();
    }
}
