// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::configuration::{
    BridgedApp, Configuration, Interface, PtpInstanceConfig, ReplaceNoneOptions, Stream,
    UnbridgedApp,
};
use anyhow::Result;
use std::collections::BTreeMap;
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

fn merge_maps<T, U>(mut map: BTreeMap<T, U>, fallback: BTreeMap<T, U>) -> BTreeMap<T, U>
where
    T: Eq + Hash + Ord,
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
    fn get_interfaces(&mut self) -> Result<BTreeMap<String, Interface>> {
        Ok(merge_maps(
            self.config.get_interfaces()?,
            self.fallback.get_interfaces()?,
        ))
    }

    fn get_interface(&mut self, interface_name: &str) -> Result<Option<Interface>> {
        let mut merged = self.config.get_interface(interface_name)?;
        merged.replace_none_options(self.fallback.get_interface(interface_name)?);
        Ok(merged)
    }

    fn get_unbridged_app(&mut self, app_name: &str) -> Result<Option<UnbridgedApp>> {
        let mut merged = self.config.get_unbridged_app(app_name)?;
        merged.replace_none_options(self.fallback.get_unbridged_app(app_name)?);
        Ok(merged)
    }

    fn get_unbridged_apps(&mut self) -> Result<BTreeMap<String, UnbridgedApp>> {
        Ok(merge_maps(
            self.config.get_unbridged_apps()?,
            self.fallback.get_unbridged_apps()?,
        ))
    }

    fn get_bridged_app(&mut self, app_name: &str) -> Result<Option<BridgedApp>> {
        let mut merged = self.config.get_bridged_app(app_name)?;
        merged.replace_none_options(self.fallback.get_bridged_app(app_name)?);
        Ok(merged)
    }

    fn get_bridged_apps(&mut self) -> Result<BTreeMap<String, BridgedApp>> {
        Ok(merge_maps(
            self.config.get_bridged_apps()?,
            self.fallback.get_bridged_apps()?,
        ))
    }

    fn get_stream(&mut self, stream_name: &str) -> Result<Option<Stream>> {
        let mut merged = self.config.get_stream(stream_name)?;
        merged.replace_none_options(self.fallback.get_stream(stream_name)?);
        Ok(merged)
    }

    fn get_streams(&mut self) -> Result<BTreeMap<String, Stream>> {
        Ok(merge_maps(
            self.config.get_streams()?,
            self.fallback.get_streams()?,
        ))
    }

    fn get_ptp_active_instance(&mut self) -> Result<Option<u32>> {
        self.config
            .get_ptp_active_instance()?
            .map_or_else(|| self.fallback.get_ptp_active_instance(), |v| Ok(Some(v)))
    }

    fn get_ptp_config(&mut self, instance: u32) -> Result<Option<PtpInstanceConfig>> {
        let mut merged = self.config.get_ptp_config(instance)?;
        merged.replace_none_options(self.fallback.get_ptp_config(instance)?);
        Ok(merged)
    }
}

#[cfg(all(test, feature = "sysrepo"))]
mod tests {
    use super::*;
    use crate::configuration::{
        Configuration, InterfaceBuilder, OutgoingL2Builder, StreamBuilder,
        StreamIdentificationBuilder, SysrepoConfiguration, YAMLConfiguration,
    };
    use const_format::concatcp;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const VERSION: &str = "0.7.0";

    #[test]
    fn test_merged_streams() -> Result<()> {
        let interface = String::from("enp86s0");
        let vid = 5;
        let expected = StreamBuilder::new()
            .incoming_interfaces(vec![format!("{interface}.{vid}")])
            .identifications(vec![StreamIdentificationBuilder::new()
                .destination_address("CB:cb:cb:cb:cb:CB".parse()?)
                .vid(vid)
                .build()])
            .outgoing_l2(vec![OutgoingL2Builder::new()
                .outgoing_interface(interface.clone())
                .priority(3)
                .build()])
            .build();

        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-successful.json",
        );

        assert_eq!(sysrepo_config.get_stream("stream0")?.unwrap(), expected);

        let yaml = format!(
            concat!(
                "version: {0}\n",
                "streams:\n",
                "  stream0:\n",
                "    incoming_interfaces: [{1}.{2}]\n",
                "    outgoing_l2:\n",
                "      - outgoing_interface: {1}\n",
            ),
            VERSION, interface, vid
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let mut merged = MergedConfiguration::new(Box::new(sysrepo_config), Box::new(config));

        assert_eq!(merged.get_stream("stream0")?.unwrap(), expected);

        Ok(())
    }

    #[test]
    fn test_merged_interfaces() -> Result<()> {
        let interface = String::from("enp86s0.5");
        let expected = InterfaceBuilder::new()
            .addresses(vec![
                (IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 24),
                (
                    IpAddr::V6(Ipv6Addr::new(0xfd2a, 0xbc93, 0x8476, 0x634, 0, 0, 0, 0)),
                    64,
                ),
            ])
            .build();
        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-successful.json",
        );
        let mut sysrepo_config_wo_ip = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-without-ip.json",
        );

        assert_eq!(sysrepo_config.get_interface(&interface)?.unwrap(), expected);

        assert_eq!(
            sysrepo_config_wo_ip.get_interface(&interface)?.unwrap(),
            InterfaceBuilder::new().build()
        );

        let yaml = format!(
            concat!(
                "version: {0}\n",
                "interfaces:\n",
                "  {1}:\n",
                "    addresses: [[192.168.2.1, 24], ['fd2a:bc93:8476:634::', 64]]\n",
            ),
            VERSION, interface
        );

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;

        let mut merged = MergedConfiguration::new(Box::new(sysrepo_config_wo_ip), Box::new(config));

        assert_eq!(merged.get_interface(&interface)?.unwrap(), expected);

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
