//! Provides YAML-based network configuration
use crate::configuration;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::io::Read;

/// Reads configuration from YAML file
#[derive(Default, Debug)]
pub struct YAMLConfiguration {
    configs: AppConfigurations,
}

type AppConfigurations = HashMap<String, configuration::AppConfig>;

impl configuration::Configuration for YAMLConfiguration {
    fn get_app_config(&mut self, app_name: &str) -> Result<configuration::AppConfig> {
        self.configs
            .get(app_name)
            .cloned()
            .ok_or_else(|| anyhow!("App {} not found in configuration!", app_name))
    }
}

impl YAMLConfiguration {
    /// Construct a new YAMLConfiguration
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
    pub fn read<R: Read>(&mut self, reader: R) -> Result<()> {
        self.configs = serde_yaml::from_reader(reader)?;
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
            "app0:\n",
            "  logical_interface: eth0.1\n",
            "  physical_interface: eth0\n",
            "  period_ns: 100000\n",
            "  offset_ns: 0\n",
            "  size_bytes: 1000\n",
            "  destination_address: cb:cb:cb:cb:cb:cb\n",
            "  vid: 1\n",
            "  pcp: 2\n",
            "  ip_address: 192.168.0.3\n",
            "  prefix_length: 16\n",
            "app1:\n",
            "  logical_interface: eth3.1\n",
            "  physical_interface: eth3\n",
            "  period_ns: 200000\n",
            "  offset_ns: 10\n",
            "  size_bytes: 2000\n",
            "  destination_address: AB:cb:cb:cb:cb:cb\n",
            "  vid: 1\n",
            "  pcp: 2\n",
            "  ip_address: 192.168.0.7\n",
            "  prefix_length: 32\n",
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let plain_config: AppConfigurations = serde_yaml::from_str(yaml)?;
        assert_eq!(config.get_app_config("app0")?, plain_config["app0"]);
        assert_eq!(config.get_app_config("app1")?, plain_config["app1"]);

        Ok(())
    }

    #[test]
    fn test_get_app_config_minimal_happy() -> Result<()> {
        let yaml = concat!(
            "app0:\n",
            "  logical_interface: eth0\n",
            "  physical_interface: eth0\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let plain_config: AppConfigurations = serde_yaml::from_str(yaml)?;
        assert_eq!(config.get_app_config("app0")?, plain_config["app0"]);

        Ok(())
    }

    #[test]
    fn test_get_app_config_happy_with_serialization() -> Result<()> {
        let app0 = configuration::AppConfig {
            logical_interface: "eth0.1".to_string(),
            physical_interface: "eth0".to_string(),
            period_ns: Some(1000 * 100),
            offset_ns: Some(0),
            size_bytes: Some(1000),
            destination_address: Some("CB:cb:cb:cb:cb:CB".parse()?),
            vid: Some(1),
            pcp: Some(2),
            ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 3))),
            prefix_length: Some(16),
        };

        let app1 = configuration::AppConfig {
            logical_interface: "eth1.2".to_string(),
            physical_interface: "eth1".to_string(),
            period_ns: Some(1000 * 120),
            offset_ns: Some(10),
            size_bytes: Some(2000),
            destination_address: Some("AB:cb:cb:cb:cb:CB".parse()?),
            vid: Some(2),
            pcp: Some(3),
            ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 2))),
            prefix_length: Some(32),
        };

        let mut configs = AppConfigurations::default();
        configs.insert("app0".to_string(), app0.clone());
        configs.insert("app1".to_string(), app1.clone());

        let yaml = serde_yaml::to_string(&configs)?;

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        assert_eq!(config.get_app_config("app0")?, app0);
        assert_eq!(config.get_app_config("app1")?, app1);

        Ok(())
    }

    #[test]
    #[should_panic(expected = "App app0 not found in configuration!")]
    fn test_get_app_config_not_found() {
        let mut config = YAMLConfiguration::default();
        config.get_app_config("app0").unwrap();
    }

    #[test]
    #[should_panic(expected = "missing field `logical_interface`")]
    fn test_read_fails() {
        let yaml = concat!(
            "app0:\n",
            "  typo_llllogical_interface: eth0.1\n",
            "  physical_interface: eth0\n",
            "  period_ns: 100000\n",
            "  offset_ns: 0\n",
            "  size_bytes: 1000\n",
            "  destination_address: cb:cb:cb:cb:cb:cb\n",
            "  vid: 1\n",
            "  pcp: 2\n"
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes()).unwrap();
    }
}
