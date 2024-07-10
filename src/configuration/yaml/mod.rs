// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Provides YAML-based network configuration

use crate::configuration::{AppConfig, Configuration, Interface, PtpInstanceConfig};
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
    apps: Option<AppConfigurations>,
    ptp: Option<PtpConfig>,
    interfaces: Option<Interfaces>,
}

#[derive(Default, Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PtpConfig {
    active_instance: Option<u32>,
    instances: Option<PtpInstanceConfigurations>,
}

type AppConfigurations = BTreeMap<String, AppConfig>;
type PtpInstanceConfigurations = BTreeMap<u32, PtpInstanceConfig>;
type Interfaces = BTreeMap<String, Interface>;

impl Configuration for YAMLConfiguration {
    fn get_interfaces(&mut self) -> Result<BTreeMap<String, Interface>> {
        Ok(self.config.interfaces.clone().unwrap_or_default())
    }

    fn get_interface(&mut self, interface_name: &str) -> Result<Option<Interface>> {
        Ok(self
            .config
            .interfaces
            .as_ref()
            .and_then(|x| x.get(interface_name).cloned()))
    }

    fn get_app_config(&mut self, app_name: &str) -> Result<Option<AppConfig>> {
        Ok(self
            .config
            .apps
            .as_ref()
            .and_then(|apps| apps.get(app_name).cloned()))
    }

    fn get_app_configs(&mut self) -> Result<AppConfigurations> {
        Ok(self.config.apps.clone().unwrap_or_default())
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
    use crate::configuration::{Configuration, StreamIdentification};
    use const_format::concatcp;
    use std::fs::File;
    const VERSION: &str = "0.5.0";

    #[test]
    fn test_get_app_config_happy() -> Result<()> {
        let yaml = concatcp!(
            "version: ",
            VERSION,
            "\n",
            "apps:\n",
            "  app0:\n",
            "    logical_interface: eth0.1\n",
            "    physical_interface: eth0\n",
            "    stream:\n",
            "      destination_address: cb:cb:cb:cb:cb:cb\n",
            "      vid: 1\n",
            "    priority: 2\n",
            "  app1:\n",
            "    logical_interface: eth3.1\n",
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
            config.get_app_config("app0")?.unwrap(),
            plain_config.apps.as_ref().unwrap()["app0"]
        );
        assert_eq!(
            config.get_app_config("app1")?.unwrap(),
            plain_config.apps.as_ref().unwrap()["app1"]
        );
        assert_eq!(
            config.get_interface("eth0.1")?.unwrap(),
            plain_config.interfaces.as_ref().unwrap()["eth0.1"]
        );

        Ok(())
    }

    #[test]
    fn test_get_app_config_minimal_happy() -> Result<()> {
        let yaml = concatcp!(
            "version: ",
            VERSION,
            "\n",
            "apps:\n",
            "  app0:\n",
            "    logical_interface: eth0\n",
            "    physical_interface: eth0\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let plain_config: Config = serde_yaml::from_str(yaml)?;
        assert_eq!(
            config.get_app_config("app0")?.unwrap(),
            plain_config.apps.unwrap()["app0"]
        );

        Ok(())
    }

    #[test]
    #[should_panic(expected = "unknown field `foo`")]
    fn test_get_app_config_additional_field() {
        let yaml = concat!(
            "foo: bar\n",
            "apps:\n",
            "  app0:\n",
            "    logical_interface: eth0\n",
            "    physical_interface: eth0\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes()).unwrap();
    }

    #[test]
    fn test_get_app_config_happy_with_serialization() -> Result<()> {
        let app_0 = AppConfig {
            logical_interface: Some("eth0.1".to_owned()),
            physical_interface: Some("eth0".to_owned()),
            stream: Some(StreamIdentification {
                destination_address: Some("CB:cb:cb:cb:cb:CB".parse()?),
                vid: Some(1),
            }),
            cgroup: None,
            priority: Some(3),
        };

        let app_1 = AppConfig {
            logical_interface: Some("eth1.2".to_owned()),
            physical_interface: Some("eth1".to_owned()),
            stream: Some(StreamIdentification {
                destination_address: Some("AB:cb:cb:cb:cb:CB".parse()?),
                vid: Some(2),
            }),
            cgroup: None,
            priority: None,
        };

        let mut apps = AppConfigurations::default();
        apps.insert("app0".to_owned(), app_0.clone());
        apps.insert("app1".to_owned(), app_1.clone());
        let config = Config {
            version: VERSION.to_owned(),
            apps: Some(apps),
            ptp: None,
            interfaces: None,
        };

        let yaml = serde_yaml::to_string(&config)?;

        let mut read_config = YAMLConfiguration::default();
        read_config.read(yaml.as_bytes())?;

        assert_eq!(read_config.get_app_config("app0")?, Some(app_0));
        assert_eq!(read_config.get_app_config("app1")?, Some(app_1));

        Ok(())
    }

    #[test]
    fn test_get_app_config_not_found() {
        let mut config = YAMLConfiguration::default();
        assert!(config.get_app_config("app0").unwrap().is_none());
    }

    #[test]
    #[should_panic(expected = "invalid type: string")]
    fn test_invalid_type() {
        let yaml = concatcp!(
            "version: ",
            VERSION,
            "\n",
            "apps:\n",
            "  app0:\n",
            "    logical_interface: eth0.1\n",
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
            "apps:\n",
            "  app0:\n",
            "    logical_interface: eth0\n",
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
            "apps:\n",
            "  app0:\n",
            "    logical_interface: eth0\n",
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
