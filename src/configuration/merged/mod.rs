// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::configuration::{
    AppConfig, Configuration, PtpInstanceConfig, ReplaceNoneOptions, TsnInterfaceConfig,
};
use anyhow::Result;
use std::collections::HashMap;
use std::hash::Hash;

/// Reads configuration from config and falls back to fallback for every option being `None`.
pub struct MergedConfiguration {
    config: Box<dyn Configuration + Send>,
    fallback: Box<dyn Configuration + Send>,
}

impl MergedConfiguration {
    /// Construct new `MergedConfiguration`.
    /// Reads configuration from config and falls back to fallback for every option being `None`.
    #[must_use]
    pub fn new(
        config: Box<dyn Configuration + Send>,
        fallback: Box<dyn Configuration + Send>,
    ) -> Self {
        Self { config, fallback }
    }
}

/// If config is None, return fallback. Otherwise and if fallback is Some, merge the two.
fn merge_structs<T: ReplaceNoneOptions>(config: Option<T>, fallback: Option<T>) -> Option<T> {
    if let Some(mut c) = config {
        if let Some(f) = fallback {
            c.replace_none_options(f);
        }

        Some(c)
    } else {
        fallback
    }
}

fn merge_maps<T, U>(mut map: HashMap<T, U>, fallback: HashMap<T, U>) -> HashMap<T, U>
where
    T: Eq + Hash,
    U: ReplaceNoneOptions,
{
    for (key, value) in fallback {
        match map.get_mut(&key) {
            Some(existing_value) => {
                existing_value.replace_none_options(value);
            }
            None => {
                map.insert(key, value);
            }
        }
    }

    map
}

impl Configuration for MergedConfiguration {
    fn get_interface_configs(&mut self) -> Result<HashMap<String, TsnInterfaceConfig>> {
        Ok(merge_maps(
            self.config.get_interface_configs()?,
            self.fallback.get_interface_configs()?,
        ))
    }

    fn get_interface_config(&mut self, interface_name: &str) -> Result<Option<TsnInterfaceConfig>> {
        Ok(merge_structs(
            self.config.get_interface_config(interface_name)?,
            self.fallback.get_interface_config(interface_name)?,
        ))
    }

    fn get_app_config(&mut self, app_name: &str) -> Result<Option<AppConfig>> {
        Ok(merge_structs(
            self.config.get_app_config(app_name)?,
            self.fallback.get_app_config(app_name)?,
        ))
    }

    fn get_app_configs(&mut self) -> Result<HashMap<String, AppConfig>> {
        Ok(merge_maps(
            self.config.get_app_configs()?,
            self.fallback.get_app_configs()?,
        ))
    }

    fn get_ptp_active_instance(&mut self) -> Result<Option<u32>> {
        self.config
            .get_ptp_active_instance()?
            .map_or_else(|| self.fallback.get_ptp_active_instance(), |v| Ok(Some(v)))
    }

    fn get_ptp_config(&mut self, instance: u32) -> Result<Option<PtpInstanceConfig>> {
        Ok(merge_structs(
            self.config.get_ptp_config(instance)?,
            self.fallback.get_ptp_config(instance)?,
        ))
    }
}

#[cfg(all(test, feature = "sysrepo"))]
mod tests {
    use super::*;
    use crate::configuration::{
        Configuration, StreamIdentification, SysrepoConfiguration, YAMLConfiguration,
    };
    use const_format::concatcp;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const VERSION: &str = "0.2.0";

    #[test]
    fn test_get_app_config_happy() -> Result<()> {
        let interface = String::from("enp86s0");
        let vid = 5;
        let expected = AppConfig {
            logical_interface: Some(format!("{interface}.{vid}")),
            physical_interface: Some(interface),
            period_ns: Some(2_000_000),
            offset_ns: Some(0),
            size_bytes: Some(15000),
            stream: Some(StreamIdentification {
                destination_address: Some("CB:cb:cb:cb:cb:CB".parse()?),
                vid: Some(vid),
            }),
            pcp: Some(3),
            addresses: Some(vec![
                (IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 24),
                (
                    IpAddr::V6(Ipv6Addr::new(0xfd2a, 0xbc93, 0x8476, 0x634, 0, 0, 0, 0)),
                    64,
                ),
            ]),
            cgroup: None,
            priority: Some(3),
        };
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-successful.json",
        );
        let mut sysrepo_config_wo_ip = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-missing-time-aware-offset.json",
        );

        assert_eq!(sysrepo_config.get_app_config("app0")?.unwrap(), expected);

        // expected not to match because addresses are missing
        assert_ne!(
            sysrepo_config_wo_ip.get_app_config("app0")?.unwrap(),
            expected
        );

        let yaml = concatcp!(
            "version: ",
            VERSION,
            "\n",
            "apps:\n",
            "  app0:\n",
            "    offset_ns: 0\n",
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let mut merged = MergedConfiguration::new(Box::new(sysrepo_config_wo_ip), Box::new(config));

        assert_eq!(merged.get_app_config("app0")?.unwrap(), expected);

        Ok(())
    }

    #[test]
    fn test_merged_ptp() -> Result<()> {
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-successful.json",
        );

        assert!(sysrepo_config.get_ptp_active_instance()?.is_none());

        let yaml = concatcp!(
            "version: ",
            VERSION,
            "\n",
            "ptp:\n",
            "  active_instance: 1\n",
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let mut merged = MergedConfiguration::new(Box::new(sysrepo_config), Box::new(config));

        let active_instance = merged.get_ptp_active_instance()?.unwrap();

        merged.get_ptp_config(active_instance).unwrap().unwrap();

        Ok(())
    }
}
