// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Provides YAML-based network configuration

use crate::configuration::{AppConfig, Configuration, PtpInstanceConfig, TsnInterfaceConfig};
use anyhow::{anyhow, Context, Result};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;

const VERSION_REQ: &str = "<=0.0.2";

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
}

#[derive(Default, Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PtpConfig {
    active_instance: Option<u32>,
    instances: Option<PtpInstanceConfigurations>,
}

type AppConfigurations = HashMap<String, AppConfig>;
type PtpInstanceConfigurations = HashMap<u32, PtpInstanceConfig>;

impl Configuration for YAMLConfiguration {
    fn get_interface_configs(&mut self) -> Result<HashMap<String, TsnInterfaceConfig>> {
        Ok(HashMap::default())
    }

    fn get_interface_config(
        &mut self,
        _interface_name: &str,
    ) -> Result<Option<TsnInterfaceConfig>> {
        Ok(None)
    }

    fn get_app_config(&mut self, app_name: &str) -> Result<Option<AppConfig>> {
        Ok(self
            .config
            .apps
            .as_ref()
            .and_then(|apps| apps.get(app_name).cloned()))
    }

    fn get_app_configs(&mut self) -> Result<AppConfigurations> {
        Ok(self.config.apps.as_ref().cloned().unwrap_or_default())
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
    use crate::configuration::Configuration;
    use const_format::concatcp;
    use std::fs::File;
    use std::net::{IpAddr, Ipv4Addr};

    const VERSION: &str = "0.0.1";

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
            "    period_ns: 100000\n",
            "    offset_ns: 0\n",
            "    size_bytes: 1000\n",
            "    destination_address: cb:cb:cb:cb:cb:cb\n",
            "    vid: 1\n",
            "    pcp: 2\n",
            "    addresses: [[192.168.0.3, 16]]\n",
            "  app1:\n",
            "    logical_interface: eth3.1\n",
            "    physical_interface: eth3\n",
            "    period_ns: 200000\n",
            "    offset_ns: 10\n",
            "    size_bytes: 2000\n",
            "    destination_address: AB:cb:cb:cb:cb:cb\n",
            "    vid: 1\n",
            "    pcp: 2\n",
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
            period_ns: Some(1000 * 100),
            offset_ns: Some(0),
            size_bytes: Some(1000),
            destination_address: Some("CB:cb:cb:cb:cb:CB".parse()?),
            vid: Some(1),
            pcp: Some(2),
            addresses: Some(vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 3)), 16)]),
            cgroup: None,
        };

        let app_1 = AppConfig {
            logical_interface: Some("eth1.2".to_owned()),
            physical_interface: Some("eth1".to_owned()),
            period_ns: Some(1000 * 120),
            offset_ns: Some(10),
            size_bytes: Some(2000),
            destination_address: Some("AB:cb:cb:cb:cb:CB".parse()?),
            vid: Some(2),
            pcp: Some(3),
            addresses: Some(vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 2)), 32)]),
            cgroup: None,
        };

        let mut apps = AppConfigurations::default();
        apps.insert("app0".to_owned(), app_0.clone());
        apps.insert("app1".to_owned(), app_1.clone());
        let config = Config {
            version: VERSION.to_owned(),
            apps: Some(apps),
            ptp: None,
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
            "    period_ns: this is no integer\n",
            "    offset_ns: 0\n",
            "    size_bytes: 1000\n",
            "    destination_address: cb:cb:cb:cb:cb:cb\n",
            "    vid: 1\n",
            "    pcp: 2\n"
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
