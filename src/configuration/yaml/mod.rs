// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Provides YAML-based network configuration

use crate::configuration::{
    BridgedApp, Configuration, Interface, PtpInstanceConfig, Stream, UnbridgedApp,
};
use anyhow::{anyhow, Context, Result};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;

const VERSION_REQ: &str = "=0.8.*";

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
    streams: Option<Streams>,
    ptp: Option<PtpConfig>,
    interfaces: Option<Interfaces>,
}

#[derive(Default, Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PtpConfig {
    active_instance: Option<u32>,
    instances: Option<PtpInstanceConfigurations>,
}

type UnbridgedApps = BTreeMap<String, UnbridgedApp>;
type BridgedApps = BTreeMap<String, BridgedApp>;
type Streams = BTreeMap<String, Stream>;
type PtpInstanceConfigurations = BTreeMap<u32, PtpInstanceConfig>;
type Interfaces = BTreeMap<String, Interface>;

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

    fn get_interfaces(&mut self) -> Result<Interfaces> {
        Ok(self.config.interfaces.clone().unwrap_or_default())
    }

    fn get_interface(&mut self, interface_name: &str) -> Result<Option<Interface>> {
        Ok(self
            .config
            .interfaces
            .as_ref()
            .and_then(|x| x.get(interface_name).cloned()))
    }

    fn get_stream(&mut self, stream_name: &str) -> Result<Option<Stream>> {
        Ok(self
            .config
            .streams
            .as_ref()
            .and_then(|streams| streams.get(stream_name).cloned()))
    }

    fn get_streams(&mut self) -> Result<Streams> {
        Ok(self.config.streams.clone().unwrap_or_default())
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
        Configuration, OutgoingL2Builder, StreamBuilder, StreamIdentification,
        StreamIdentificationBuilder,
    };
    use const_format::concatcp;
    use std::fs::File;
    const VERSION: &str = "0.8.0";

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
            "    priority: 2\n",
            "  app1:\n",
            "    bind_interface: eth3.1\n",
            "    physical_interface: eth3\n",
            "    stream:\n",
            "      destination_address: AB:cb:cb:cb:cb:cb\n",
            "      vid: 1\n",
            "    priority: 3\n",
            "interfaces:\n",
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
            "  eth0.1:\n",
            "    addresses: [[192.168.0.3, 16]]\n",
            "  eth3.1:\n",
            "    addresses: [[192.168.0.7, 32]]\n",
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
        assert_eq!(
            config.get_interface("eth0.1")?.unwrap(),
            plain_config.interfaces.as_ref().unwrap()["eth0.1"]
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
            streams: None,
            ptp: None,
            interfaces: None,
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
    fn test_get_bridged_app_and_stream_happy() -> Result<()> {
        let yaml = concatcp!(
            "version: ",
            VERSION,
            "\n",
            "bridged_apps:\n",
            "  app0:\n",
            "    vlans: [1]\n",
            "    virtual_interface_app: veth0\n",
            "    netns_app: app0\n",
            "    virtual_interface_bridge: vethapp0\n",
            "streams:\n",
            "  stream0:\n",
            "    incoming_interfaces: [vethapp0]\n",
            "    identifications:\n",
            "      - destination_address: cb:cb:cb:cb:cb:cb\n",
            "        vid: 1\n",
            "    outgoing_l2:\n",
            "      - outgoing_interface: eth0\n",
            "  stream1:\n",
            "    incoming_interfaces: [eth1]\n",
            "    identifications:\n",
            "      - destination_address: AB:cb:cb:cb:cb:cb\n",
            "        vid: 1\n",
            "    outgoing_l2:\n",
            "      - outgoing_interface: eth3\n",
            "interfaces:\n",
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
            "  eth0.1:\n",
            "    addresses: [[192.168.0.3, 16]]\n",
            "  eth3.1:\n",
            "    addresses: [[192.168.0.7, 32]]\n",
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let plain_config: Config = serde_yaml::from_str(yaml)?;
        assert_eq!(
            config.get_bridged_app("app0")?.unwrap(),
            plain_config.bridged_apps.as_ref().unwrap()["app0"]
        );
        assert_eq!(
            config.get_stream("stream0")?.unwrap(),
            plain_config.streams.as_ref().unwrap()["stream0"]
        );
        assert_eq!(
            config.get_stream("stream1")?.unwrap(),
            plain_config.streams.as_ref().unwrap()["stream1"]
        );

        Ok(())
    }

    #[test]
    fn test_get_stream_minimal_happy() -> Result<()> {
        let yaml = concatcp!(
            "version: ",
            VERSION,
            "\n",
            "streams:\n",
            "  stream0:\n",
            "    incoming_interfaces: [eth0]\n",
            "    outgoing_l2:\n",
            "      - outgoing_interface: eth0\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let plain_config: Config = serde_yaml::from_str(yaml)?;
        assert_eq!(
            config.get_stream("stream0")?.unwrap(),
            plain_config.streams.unwrap()["stream0"]
        );

        Ok(())
    }

    #[test]
    #[should_panic(expected = "unknown field `foo`")]
    fn test_get_stream_additional_field() {
        let yaml = concat!(
            "foo: bar\n",
            "streams:\n",
            "  stream0:\n",
            "    incoming_interfaces: [eth0]\n",
            "    outgoing_l2:\n",
            "      outgoing_interface: eth0\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes()).unwrap();
    }

    #[test]
    fn test_get_stream_happy_with_serialization() -> Result<()> {
        let stream_0 = StreamBuilder::new()
            .incoming_interfaces(vec!["eth0.1".to_owned()])
            .identifications(vec![StreamIdentificationBuilder::new()
                .destination_address("CB:cb:cb:cb:cb:CB".parse()?)
                .vid(1)
                .build()])
            .outgoing_l2(vec![OutgoingL2Builder::new()
                .outgoing_interface("eth0".to_owned())
                .build()])
            .build();

        let stream_1 = StreamBuilder::new()
            .incoming_interfaces(vec!["eth1.2".to_owned()])
            .identifications(vec![StreamIdentificationBuilder::new()
                .destination_address("CB:cb:cb:cb:cb:CB".parse()?)
                .vid(2)
                .build()])
            .outgoing_l2(vec![OutgoingL2Builder::new()
                .outgoing_interface("eth1".to_owned())
                .build()])
            .build();

        let mut streams = Streams::default();
        streams.insert("stream0".to_owned(), stream_0.clone());
        streams.insert("stream1".to_owned(), stream_1.clone());
        let config = Config {
            version: VERSION.to_owned(),
            unbridged_apps: None,
            bridged_apps: None,
            streams: Some(streams),
            ptp: None,
            interfaces: None,
        };

        let yaml = serde_yaml::to_string(&config)?;

        let mut read_config = YAMLConfiguration::default();
        read_config.read(yaml.as_bytes())?;

        assert_eq!(read_config.get_stream("stream0")?, Some(stream_0));
        assert_eq!(read_config.get_stream("stream1")?, Some(stream_1));

        Ok(())
    }

    #[test]
    fn test_get_stream_config_not_found() {
        let mut config = YAMLConfiguration::default();
        assert!(config.get_stream("stream0").unwrap().is_none());
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
    fn validate_example_yamls() {
        let mut config = YAMLConfiguration::default();
        config
            .read(File::open("./config/yaml/unbridged.yml").unwrap())
            .unwrap();

        config = YAMLConfiguration::default();
        config
            .read(File::open("./config/yaml/bridged.yml").unwrap())
            .unwrap();
    }
}
