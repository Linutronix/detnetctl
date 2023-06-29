// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Provides YAML-based network configuration

use crate::configuration;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;

/// Reads configuration from YAML file
#[derive(Default, Debug)]
pub struct YAMLConfiguration {
    config: Config,
}

#[derive(Default, Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Config {
    apps: Option<AppConfigurations>,
    ptp: Option<PtpConfigurations>,
}

type AppConfigurations = HashMap<String, configuration::AppConfig>;
type PtpConfigurations = HashMap<u32, configuration::PtpConfig>;

impl configuration::Configuration for YAMLConfiguration {
    fn get_app_config(&mut self, app_name: &str) -> Result<configuration::AppConfig> {
        self.config.apps.as_ref().map_or_else(
            || Err(anyhow!("No apps section found in configuration!")),
            |apps| {
                apps.get(app_name)
                    .cloned()
                    .ok_or_else(|| anyhow!("App {} not found in configuration!", app_name))
            },
        )
    }

    fn get_ptp_config(&mut self, instance: u32) -> Result<configuration::PtpConfig> {
        self.config.ptp.as_ref().map_or_else(
            || Err(anyhow!("No ptp section found in configuration!")),
            |ptp| {
                ptp.get(&instance)
                    .cloned()
                    .ok_or_else(|| anyhow!("PTP instance {} not found in configuration!", instance))
            },
        )
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::Configuration;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_get_app_config_happy() -> Result<()> {
        let yaml = concat!(
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
            config.get_app_config("app0")?,
            plain_config.apps.as_ref().unwrap()["app0"]
        );
        assert_eq!(
            config.get_app_config("app1")?,
            plain_config.apps.as_ref().unwrap()["app1"]
        );

        Ok(())
    }

    #[test]
    fn test_get_app_config_minimal_happy() -> Result<()> {
        let yaml = concat!(
            "apps:\n",
            "  app0:\n",
            "    logical_interface: eth0\n",
            "    physical_interface: eth0\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let plain_config: Config = serde_yaml::from_str(yaml)?;
        assert_eq!(
            config.get_app_config("app0")?,
            plain_config.apps.unwrap()["app0"]
        );

        Ok(())
    }

    #[test]
    fn test_get_app_config_happy_with_serialization() -> Result<()> {
        let app_0 = configuration::AppConfig {
            logical_interface: "eth0.1".to_owned(),
            physical_interface: "eth0".to_owned(),
            period_ns: Some(1000 * 100),
            offset_ns: Some(0),
            size_bytes: Some(1000),
            destination_address: Some("CB:cb:cb:cb:cb:CB".parse()?),
            vid: Some(1),
            pcp: Some(2),
            addresses: Some(vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 3)), 16)]),
        };

        let app_1 = configuration::AppConfig {
            logical_interface: "eth1.2".to_owned(),
            physical_interface: "eth1".to_owned(),
            period_ns: Some(1000 * 120),
            offset_ns: Some(10),
            size_bytes: Some(2000),
            destination_address: Some("AB:cb:cb:cb:cb:CB".parse()?),
            vid: Some(2),
            pcp: Some(3),
            addresses: Some(vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 2)), 32)]),
        };

        let mut apps = AppConfigurations::default();
        apps.insert("app0".to_owned(), app_0.clone());
        apps.insert("app1".to_owned(), app_1.clone());
        let config = Config {
            apps: Some(apps),
            ptp: None,
        };

        let yaml = serde_yaml::to_string(&config)?;

        let mut read_config = YAMLConfiguration::default();
        read_config.read(yaml.as_bytes())?;

        assert_eq!(read_config.get_app_config("app0")?, app_0);
        assert_eq!(read_config.get_app_config("app1")?, app_1);

        Ok(())
    }

    #[test]
    #[should_panic(expected = "No apps section found in configuration!")]
    fn test_get_app_config_not_found() {
        let mut config = YAMLConfiguration::default();
        config.get_app_config("app0").unwrap();
    }

    #[test]
    #[should_panic(expected = "missing field `logical_interface`")]
    fn test_read_fails() {
        let yaml = concat!(
            "apps:\n",
            "  app0:\n",
            "    typo_llllogical_interface: eth0.1\n",
            "    physical_interface: eth0\n",
            "    period_ns: 100000\n",
            "    offset_ns: 0\n",
            "    size_bytes: 1000\n",
            "    destination_address: cb:cb:cb:cb:cb:cb\n",
            "    vid: 1\n",
            "    pcp: 2\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes()).unwrap();
    }
}
