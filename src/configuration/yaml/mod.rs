// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Provides YAML-based network configuration

use crate::configuration::{
    BridgedApp, Configuration, Flow, PhysicalInterface, PtpInstanceConfig, UnbridgedApp,
};
use anyhow::{anyhow, Context, Result};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;

const VERSION_REQ: &str = "=0.5.*";

/// Reads configuration from YAML file
#[derive(Default, Debug)]
pub struct YAMLConfiguration {
    config: Config,
}

#[derive(Default, Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: String,
    unbridged_apps: Option<UnbridgedApps>,
    bridged_apps: Option<BridgedApps>,
    flows: Option<Flows>,
    ptp: Option<PtpConfig>,
    physical_interfaces: Option<PhysicalInterfaces>,
}

#[derive(Default, Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PtpConfig {
    active_instance: Option<u32>,
    instances: Option<PtpInstanceConfigurations>,
}

type UnbridgedApps = BTreeMap<String, UnbridgedApp>;
type BridgedApps = BTreeMap<String, BridgedApp>;
type Flows = BTreeMap<String, Flow>;
type PtpInstanceConfigurations = BTreeMap<u32, PtpInstanceConfig>;
type PhysicalInterfaces = BTreeMap<String, PhysicalInterface>;

impl Configuration for YAMLConfiguration {
    fn get_unbridged_app(&mut self, app_name: &str) -> Result<Option<UnbridgedApp>> {
        Ok(self
            .config
            .unbridged_apps
            .as_ref()
            .and_then(|unbridged_apps| unbridged_apps.get(app_name).cloned()))
    }

    fn get_unbridged_apps(&mut self) -> Result<UnbridgedApps> {
        Ok(self.config.unbridged_apps.clone().unwrap_or_default())
    }

    fn get_bridged_app(&mut self, app_name: &str) -> Result<Option<BridgedApp>> {
        Ok(self
            .config
            .bridged_apps
            .as_ref()
            .and_then(|bridged_apps| bridged_apps.get(app_name).cloned()))
    }

    fn get_bridged_apps(&mut self) -> Result<BridgedApps> {
        Ok(self.config.bridged_apps.clone().unwrap_or_default())
    }

    fn get_physical_interfaces(&mut self) -> Result<PhysicalInterfaces> {
        Ok(self.config.physical_interfaces.clone().unwrap_or_default())
    }

    fn get_physical_interface(
        &mut self,
        interface_name: &str,
    ) -> Result<Option<PhysicalInterface>> {
        Ok(self
            .config
            .physical_interfaces
            .as_ref()
            .and_then(|x| x.get(interface_name).cloned()))
    }

    fn get_flow(&mut self, flow_name: &str) -> Result<Option<Flow>> {
        Ok(self
            .config
            .flows
            .as_ref()
            .and_then(|flows| flows.get(flow_name).cloned()))
    }

    fn get_flows(&mut self) -> Result<Flows> {
        Ok(self.config.flows.clone().unwrap_or_default())
    }

    fn get_ptp_active_instance(&mut self) -> Result<Option<u32>> {
        Ok(self.config.ptp.as_ref().and_then(|ptp| ptp.active_instance))
    }

    fn get_ptp_config(&mut self, instance: u32) -> Result<Option<PtpInstanceConfig>> {
        Ok(self
            .config
            .ptp
            .as_ref()
            .and_then(|ptp| ptp.instances.as_ref())
            .and_then(|instances| instances.get(&instance))
            .cloned())
    }
}

impl YAMLConfiguration {
    /// Construct a new `YAMLConfiguration`
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read YAML from a reader
    ///
    /// ```
    /// # use detnetctl::configuration::{Configuration, YAMLConfiguration};
    /// # #[path = "../doctest.rs"]
    /// # mod doctest;
    /// # let tmpfile = doctest::generate_example_yaml();
    /// # let filepath = tmpfile.path();
    /// # use std::fs::File;
    /// # let mut yaml_config = YAMLConfiguration::new();
    /// yaml_config.read(File::open(filepath)?)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Will return `Err` if the configuration could not be parsed.
    pub fn read<R: Read>(&mut self, reader: R) -> Result<()> {
        self.config = serde_yaml::from_reader(reader).context("Reading YAML file")?;

        if !VersionReq::parse(VERSION_REQ)?.matches(&Version::parse(&self.config.version)?) {
            return Err(anyhow!(
                "File configuration version \"{}\" is not matching expected \"{VERSION_REQ}\"",
                self.config.version
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{
        AppFlowBuilder, Configuration, FlowBuilder, StreamIdentification,
        StreamIdentificationBuilder, TsnNextHopBuilder,
    };
    use const_format::concatcp;
    use std::fs::File;
    use std::net::{IpAddr, Ipv4Addr};
    const VERSION: &str = "0.5.0";

    #[test]
    fn test_get_unbridged_app_happy() -> Result<()> {
        let yaml = concatcp!(
            "version: ",
            VERSION,
            "\n",
            "unbridged_apps:\n",
            "  app0:\n",
            "    bind_interface: eth0.1\n",
            "    physical_interface: eth0\n",
            "    stream:\n",
            "      destination_address: cb:cb:cb:cb:cb:cb\n",
            "      vid: 1\n",
            "    addresses: [[192.168.0.3, 16]]\n",
            "    priority: 2\n",
            "  app1:\n",
            "    bind_interface: eth3.1\n",
            "    physical_interface: eth3\n",
            "    stream:\n",
            "      destination_address: AB:cb:cb:cb:cb:cb\n",
            "      vid: 1\n",
            "    addresses: [[192.168.0.7, 32]]\n",
            "    priority: 3\n",
            "physical_interfaces:\n",
            "  eth0:\n",
            "    schedule:\n",
            "      number_of_traffic_classes: 3\n",
            "      priority_map:\n",
            "        0: 0\n",
            "        1: 2\n",
            "      basetime_ns: 1000\n",
            "      control_list:\n",
            "        - operation: SetGates\n",
            "          time_interval_ns: 10\n",
            "          traffic_classes: [0]\n",
            "        - operation: SetGates\n",
            "          time_interval_ns: 20\n",
            "          traffic_classes: [2]\n",
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let plain_config: Config = serde_yaml::from_str(yaml)?;
        assert_eq!(
            config.get_unbridged_app("app0")?.unwrap(),
            plain_config.unbridged_apps.as_ref().unwrap()["app0"]
        );
        assert_eq!(
            config.get_unbridged_app("app1")?.unwrap(),
            plain_config.unbridged_apps.as_ref().unwrap()["app1"]
        );

        Ok(())
    }

    #[test]
    fn test_get_unbridged_app_minimal_happy() -> Result<()> {
        let yaml = concatcp!(
            "version: ",
            VERSION,
            "\n",
            "unbridged_apps:\n",
            "  app0:\n",
            "    bind_interface: eth0\n",
            "    physical_interface: eth0\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let plain_config: Config = serde_yaml::from_str(yaml)?;
        assert_eq!(
            config.get_unbridged_app("app0")?.unwrap(),
            plain_config.unbridged_apps.unwrap()["app0"]
        );

        Ok(())
    }

    #[test]
    #[should_panic(expected = "unknown field `foo`")]
    fn test_get_unbridged_app_additional_field() {
        let yaml = concat!(
            "foo: bar\n",
            "unbridged_apps:\n",
            "  app0:\n",
            "    bind_interface: eth0\n",
            "    physical_interface: eth0\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes()).unwrap();
    }

    #[test]
    fn test_get_unbridged_app_happy_with_serialization() -> Result<()> {
        let app_0 = UnbridgedApp {
            bind_interface: Some("eth0.1".to_owned()),
            physical_interface: Some("eth0".to_owned()),
            stream: Some(StreamIdentification {
                destination_address: Some("CB:cb:cb:cb:cb:CB".parse()?),
                vid: Some(1),
            }),
            addresses: Some(vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 3)), 16)]),
            cgroup: None,
            priority: Some(3),
        };

        let app_1 = UnbridgedApp {
            bind_interface: Some("eth1.2".to_owned()),
            physical_interface: Some("eth1".to_owned()),
            stream: Some(StreamIdentification {
                destination_address: Some("AB:cb:cb:cb:cb:CB".parse()?),
                vid: Some(2),
            }),
            addresses: Some(vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 2)), 32)]),
            cgroup: None,
            priority: None,
        };

        let mut apps = UnbridgedApps::default();
        apps.insert("app0".to_owned(), app_0.clone());
        apps.insert("app1".to_owned(), app_1.clone());
        let config = Config {
            version: VERSION.to_owned(),
            unbridged_apps: Some(apps),
            bridged_apps: None,
            flows: None,
            ptp: None,
            physical_interfaces: None,
        };

        let yaml = serde_yaml::to_string(&config)?;

        let mut read_config = YAMLConfiguration::default();
        read_config.read(yaml.as_bytes())?;

        assert_eq!(read_config.get_unbridged_app("app0")?, Some(app_0));
        assert_eq!(read_config.get_unbridged_app("app1")?, Some(app_1));

        Ok(())
    }

    #[test]
    fn test_get_unbridged_app_not_found() {
        let mut config = YAMLConfiguration::default();
        assert!(config.get_unbridged_app("app0").unwrap().is_none());
    }

    #[test]
    fn test_get_flow_happy() -> Result<()> {
        let yaml = concatcp!(
            "version: ",
            VERSION,
            "\n",
            "flows:\n",
            "  appflow0:\n",
            "    app:\n",
            "      ingress_interface: eth0.1\n",
            "      stream:\n",
            "        destination_address: cb:cb:cb:cb:cb:cb\n",
            "        vid: 1\n",
            "      addresses: [[192.168.0.3, 16]]\n",
            "    next_hop:\n",
            "      outgoing_interface: eth0\n",
            "      priority: 2\n",
            "  appflow1:\n",
            "    app:\n",
            "      ingress_interface: eth3.1\n",
            "      stream:\n",
            "        destination_address: AB:cb:cb:cb:cb:cb\n",
            "        vid: 1\n",
            "      addresses: [[192.168.0.7, 32]]\n",
            "    next_hop:\n",
            "      outgoing_interface: eth3\n",
            "      priority: 3\n",
            "physical_interfaces:\n",
            "  eth0:\n",
            "    schedule:\n",
            "      number_of_traffic_classes: 3\n",
            "      priority_map:\n",
            "        0: 0\n",
            "        1: 2\n",
            "      basetime_ns: 1000\n",
            "      control_list:\n",
            "        - operation: SetGates\n",
            "          time_interval_ns: 10\n",
            "          traffic_classes: [0]\n",
            "        - operation: SetGates\n",
            "          time_interval_ns: 20\n",
            "          traffic_classes: [2]\n",
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let plain_config: Config = serde_yaml::from_str(yaml)?;
        assert_eq!(
            config.get_flow("appflow0")?.unwrap(),
            plain_config.flows.as_ref().unwrap()["appflow0"]
        );
        assert_eq!(
            config.get_flow("appflow1")?.unwrap(),
            plain_config.flows.as_ref().unwrap()["appflow1"]
        );

        Ok(())
    }

    #[test]
    fn test_get_flow_minimal_happy() -> Result<()> {
        let yaml = concatcp!(
            "version: ",
            VERSION,
            "\n",
            "flows:\n",
            "  appflow0:\n",
            "    app:\n",
            "      ingress_interface: eth0\n",
            "    next_hop:\n",
            "      outgoing_interface: eth0\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let plain_config: Config = serde_yaml::from_str(yaml)?;
        assert_eq!(
            config.get_flow("appflow0")?.unwrap(),
            plain_config.flows.unwrap()["appflow0"]
        );

        Ok(())
    }

    #[test]
    #[should_panic(expected = "unknown field `foo`")]
    fn test_get_flow_additional_field() {
        let yaml = concat!(
            "foo: bar\n",
            "flows:\n",
            "  appflow0:\n",
            "    app:\n",
            "      ingress_interface: eth0\n",
            "    next_hop:\n",
            "      outgoing_interface: eth0\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes()).unwrap();
    }

    #[test]
    fn test_get_flow_happy_with_serialization() -> Result<()> {
        let flow_0 = FlowBuilder::new()
            .app(
                AppFlowBuilder::new()
                    .ingress_interface("eth0.1".to_owned())
                    .stream(
                        StreamIdentificationBuilder::new()
                            .destination_address("CB:cb:cb:cb:cb:CB".parse()?)
                            .vid(1)
                            .build(),
                    )
                    .addresses(vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 3)), 16)])
                    .build(),
            )
            .next_hop(
                TsnNextHopBuilder::new()
                    .outgoing_interface("eth0".to_owned())
                    .priority(3)
                    .build(),
            )
            .build();

        let flow_1 = FlowBuilder::new()
            .app(
                AppFlowBuilder::new()
                    .ingress_interface("eth1.2".to_owned())
                    .stream(
                        StreamIdentificationBuilder::new()
                            .destination_address("CB:cb:cb:cb:cb:CB".parse()?)
                            .vid(2)
                            .build(),
                    )
                    .addresses(vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 2)), 32)])
                    .build(),
            )
            .next_hop(
                TsnNextHopBuilder::new()
                    .outgoing_interface("eth1".to_owned())
                    .build(),
            )
            .build();

        let mut flows = Flows::default();
        flows.insert("appflow0".to_owned(), flow_0.clone());
        flows.insert("appflow1".to_owned(), flow_1.clone());
        let config = Config {
            version: VERSION.to_owned(),
            unbridged_apps: None,
            bridged_apps: None,
            flows: Some(flows),
            ptp: None,
            physical_interfaces: None,
        };

        let yaml = serde_yaml::to_string(&config)?;

        let mut read_config = YAMLConfiguration::default();
        read_config.read(yaml.as_bytes())?;

        assert_eq!(read_config.get_flow("appflow0")?, Some(flow_0));
        assert_eq!(read_config.get_flow("appflow1")?, Some(flow_1));

        Ok(())
    }

    #[test]
    fn test_get_flow_config_not_found() {
        let mut config = YAMLConfiguration::default();
        assert!(config.get_flow("appflow0").unwrap().is_none());
    }

    #[test]
    #[should_panic(expected = "invalid type: string")]
    fn test_invalid_type() {
        let yaml = concatcp!(
            "version: ",
            VERSION,
            "\n",
            "unbridged_apps:\n",
            "  app0:\n",
            "    bind_interface: eth0.1\n",
            "    physical_interface: eth0\n",
            "    stream:\n",
            "      destination_address: cb:cb:cb:cb:cb:cb\n",
            "      vid: this is no integer\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes()).unwrap();
    }

    #[test]
    #[should_panic(expected = "missing field `version`")]
    fn test_no_version() {
        let yaml = concat!(
            "unbridged_apps:\n",
            "  app0:\n",
            "    bind_interface: eth0\n",
            "    physical_interface: eth0\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes()).unwrap();
    }

    #[test]
    #[should_panic(expected = "File configuration version \"99999.0.0\" is not matching expected")]
    fn test_wrong_version() {
        let yaml = concat!(
            "version: 99999.0.0\n",
            "unbridged_apps:\n",
            "  app0:\n",
            "    bind_interface: eth0\n",
            "    physical_interface: eth0\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes()).unwrap();
    }

    #[test]
    fn validate_example_yaml() {
        let mut config = YAMLConfiguration::default();
        config
            .read(File::open("./config/yaml/example.yml").unwrap())
            .unwrap();
    }
}
