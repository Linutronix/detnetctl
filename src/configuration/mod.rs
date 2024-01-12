// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Provides the network configuration
//!
//! With YAML configuration:
//!
//! ```
//! use detnetctl::configuration::{Configuration, YAMLConfiguration};
//! # #[path = "doctest.rs"]
//! # mod doctest;
//! # let tmpfile = doctest::generate_example_yaml();
//! # let filepath = tmpfile.path();
//! use std::fs::File;
//!
//! let mut yaml_config = YAMLConfiguration::new();
//! yaml_config.read(File::open(filepath)?)?;
//! let config = yaml_config.get_app_config("app0")?;
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! With sysrepo configuration (for NETCONF integration):
#![cfg_attr(not(feature = "sysrepo"), doc = "```ignore")]
#![cfg_attr(feature = "sysrepo", doc = "```no_run")]
//! use detnetctl::configuration::{Configuration, SysrepoConfiguration};
//! let mut sysrepo_config = SysrepoConfiguration::new()?;
//! let config = sysrepo_config.get_app_config("app0");
//! # Ok::<(), anyhow::Error>(())
//! ```
use crate::ptp::PtpInstanceConfig;
use anyhow::{anyhow, Result};
use eui48::MacAddress;
use options_struct_derive::{OptionsBuilder, OptionsGetters, ReplaceNoneOptions};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

/// Merge two structs by replacing None options with the fallback
pub trait ReplaceNoneOptions {
    /// Replace all options that are None with the corresponding value from fallback
    fn replace_none_options(&mut self, fallback: Self);
}

/// Fill unset parameters with defaults where applicable and validate
pub trait FillDefaults {
    /// Fill unset fields with defaults if resonable ones can be calculated
    ///
    /// # Errors
    ///
    /// Returns error if calculating the defaults is not possible.
    fn fill_defaults(&mut self) -> Result<()>;
}

#[cfg(test)]
use mockall::automock;

/// Contains the configuration for a TSN/DetNet application
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    ReplaceNoneOptions,
    OptionsGetters,
    OptionsBuilder,
)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// Logical interface for the application to bind to (usually a VLAN interface like eth0.2)
    logical_interface: Option<String>,

    /// Physical interface corresponding to the logical interface
    physical_interface: Option<String>,

    /// Reference time period for traffic specification
    period_ns: Option<u32>,

    /// Time slot offset within period
    ///
    /// It COULD be calculated locally if latency and jitter are not relevant,
    /// otherwise a network-wide calculation (central or decentral) is required
    /// so that packets can optimally directly be forwarded WITHIN the period.
    offset_ns: Option<u32>,

    /// Used to calculate length of the time slot
    size_bytes: Option<u32>,

    /// Destination MAC address
    #[serde(default, with = "serialize_mac_address")]
    destination_address: Option<MacAddress>,

    /// VLAN-Identifier
    vid: Option<u16>, // actually 12 bit

    /// Priority Code Point
    pcp: Option<u8>, // actually 3 bit

    /// IP addresses and prefix lengths of the logical interface
    addresses: Option<Vec<(IpAddr, u8)>>,

    /// Allow only processes within this cgroup to generate traffic for this app
    cgroup: Option<PathBuf>,
}

mod schedule;
pub use schedule::{GateControlEntry, GateOperation, Schedule, ScheduleBuilder};

/// Contains the configuration for a TSN interface
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    ReplaceNoneOptions,
    OptionsGetters,
    OptionsBuilder,
)]
pub struct TsnInterfaceConfig {
    /// Qbv schedule
    pub schedule: Option<Schedule>,
}

impl FillDefaults for TsnInterfaceConfig {
    fn fill_defaults(&mut self) -> Result<()> {
        if let Some(schedule) = self.schedule.as_mut() {
            schedule.fill_defaults()?;
        } else {
            let mut schedule = ScheduleBuilder::new().build();
            schedule.fill_defaults()?;
            self.schedule = Some(schedule);
        }

        Ok(())
    }
}

mod serialize_mac_address {
    use eui48::MacAddress;
    use serde::{self, Deserialize, Deserializer, Serializer};

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(crate) fn serialize<S>(addr: &Option<MacAddress>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = addr.map_or_else(String::new, |a| a.to_hex_string());
        serializer.serialize_str(&s)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<MacAddress>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            Ok(None)
        } else {
            MacAddress::parse_str(&s)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
    }
}

/// Defines how to request the configuration
#[cfg_attr(test, automock)]
pub trait Configuration {
    /// Get all interface configurations
    ///
    /// # Errors
    ///
    /// Will return `Err` if there is a general problem reading the configuration.
    fn get_interface_configs(&mut self) -> Result<HashMap<String, TsnInterfaceConfig>>;

    /// Get configuration for the given interface
    ///
    /// # Errors
    ///
    /// Will return `Err` if there is a general problem reading the configuration.
    /// If no interface was found for that `interface_name`, Ok(None) is returned.
    fn get_interface_config(&mut self, interface_name: &str) -> Result<Option<TsnInterfaceConfig>>;

    /// Get the configuration for a given `app_name`
    ///
    /// # Errors
    ///
    /// Will return `Err` if there is a general problem reading the configuration.
    /// If no `AppConfig` is found for the name, Ok(None) is returned.
    fn get_app_config(&mut self, app_name: &str) -> Result<Option<AppConfig>>;

    /// Get the configuration for all provided apps
    ///
    /// # Errors
    ///
    /// Will return `Err` if there is a general problem reading the configuration.
    fn get_app_configs(&mut self) -> Result<HashMap<String, AppConfig>>;

    /// Get the configured active PTP instance
    ///
    /// # Errors
    ///
    /// Will return `Err` if there is a general problem reading the configuration.
    /// If no active instance is configured, Ok(None) is returned.
    fn get_ptp_active_instance(&mut self) -> Result<Option<u32>>;

    /// Get the PTP configuration for a given instance
    ///
    /// # Errors
    ///
    /// Will return `Err` if there is a general problem reading the configuration.
    /// If no `PtpInstanceConfig` is found for the instance, Ok(None) is returned.
    fn get_ptp_config(&mut self, instance: u32) -> Result<Option<PtpInstanceConfig>>;
}

mod yaml;
pub use yaml::YAMLConfiguration;

#[cfg(feature = "sysrepo")]
mod sysrepo;
#[cfg(feature = "sysrepo")]
pub use self::sysrepo::SysrepoConfiguration;

mod merged;
pub use merged::MergedConfiguration;

#[cfg(test)]
mod tests {
    use super::*;
    use options_struct_derive::validate_are_some;

    #[test]
    fn validate_happy() {
        let app_config = AppConfigBuilder::new()
            .logical_interface("eth0.3".to_owned())
            .build();

        validate_are_some!(app_config, logical_interface).unwrap();
    }

    #[test]
    #[should_panic(expected = "Validation failed! physical_interface is missing for app_config")]
    fn validate_fails() {
        let app_config = AppConfigBuilder::new()
            .logical_interface("eth0.3".to_owned())
            .build();

        validate_are_some!(app_config, physical_interface).unwrap();
    }

    #[test]
    #[should_panic(expected = "Required field physical_interface is missing in AppConfig")]
    fn access_fails() {
        let app_config = AppConfigBuilder::new()
            .logical_interface("eth0.3".to_owned())
            .build();

        assert!(app_config.logical_interface_is_some());
        assert!(!app_config.physical_interface_is_some());
        app_config.logical_interface().unwrap();
        app_config.physical_interface().unwrap();
    }
}
