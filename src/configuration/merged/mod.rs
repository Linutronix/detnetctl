// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::configuration::{
    BridgedApp, Configuration, Flow, PhysicalInterface, PtpInstanceConfig, ReplaceNoneOptions,
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
    fn get_physical_interfaces(&mut self) -> Result<BTreeMap<String, PhysicalInterface>> {
        Ok(merge_maps(
            self.config.get_physical_interfaces()?,
            self.fallback.get_physical_interfaces()?,
        ))
    }

    fn get_physical_interface(
        &mut self,
        interface_name: &str,
    ) -> Result<Option<PhysicalInterface>> {
        let mut merged = self.config.get_physical_interface(interface_name)?;
        merged.replace_none_options(self.fallback.get_physical_interface(interface_name)?);
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

    fn get_flow(&mut self, flow_name: &str) -> Result<Option<Flow>> {
        let mut merged = self.config.get_flow(flow_name)?;
        merged.replace_none_options(self.fallback.get_flow(flow_name)?);
        Ok(merged)
    }

    fn get_flows(&mut self) -> Result<BTreeMap<String, Flow>> {
        Ok(merge_maps(
            self.config.get_flows()?,
            self.fallback.get_flows()?,
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
        AppFlowBuilder, Configuration, FlowBuilder, StreamIdentificationBuilder,
        SysrepoConfiguration, TsnNextHopBuilder, YAMLConfiguration,
    };
    use const_format::concatcp;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const VERSION: &str = "0.5.0";

    #[test]
    fn test_get_flow_config_happy() -> Result<()> {
        let interface = String::from("enp86s0");
        let vid = 5;
        let expected = FlowBuilder::new()
            .app(
                AppFlowBuilder::new()
                    .ingress_interface(format!("{interface}.{vid}"))
                    .stream(
                        StreamIdentificationBuilder::new()
                            .destination_address("CB:cb:cb:cb:cb:CB".parse()?)
                            .vid(vid)
                            .build(),
                    )
                    .addresses(vec![
                        (IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 24),
                        (
                            IpAddr::V6(Ipv6Addr::new(0xfd2a, 0xbc93, 0x8476, 0x634, 0, 0, 0, 0)),
                            64,
                        ),
                    ])
                    .build(),
            )
            .next_hop(
                TsnNextHopBuilder::new()
                    .outgoing_interface(interface.clone())
                    .priority(3)
                    .build(),
            )
            .build();

        let mut sysrepo_config = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-successful.json",
        );
        let mut sysrepo_config_wo_ip = SysrepoConfiguration::mock_from_file(
            "./src/configuration/sysrepo/test-without-ip.json",
        );

        assert_eq!(sysrepo_config.get_flow("appflow0")?.unwrap(), expected);

        // expected not to match because addresses are missing
        assert_ne!(
            sysrepo_config_wo_ip.get_flow("appflow0")?.unwrap(),
            expected
        );

        println!("{:?}", sysrepo_config_wo_ip.get_flow("appflow0")?.unwrap());

        let yaml = format!(
            concat!(
                "version: {0}\n",
                "flows:\n",
                "  appflow0:\n",
                "    app:\n",
                "      ingress_interface: {1}.{2}\n",
                "      addresses: [[192.168.2.1, 24], ['fd2a:bc93:8476:634::', 64]]\n",
                "    next_hop:\n",
                "      outgoing_interface: {1}\n",
            ),
            VERSION, interface, vid
        );
        println!("{yaml}");

        let mut config = YAMLConfiguration::default();
        config.read(yaml.as_bytes())?;
        println!("{config:?}");

        let mut merged = MergedConfiguration::new(Box::new(sysrepo_config_wo_ip), Box::new(config));

        assert_eq!(merged.get_flow("appflow0")?.unwrap(), expected);

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
