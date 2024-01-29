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
use anyhow::Result;
use eui48::MacAddress;
use replace_none_options_derive::ReplaceNoneOptions;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

/// Merge two structs by replacing None options with the fallback
pub trait ReplaceNoneOptions {
    /// Replace all options that are None with the corresponding value from fallback
    fn replace_none_options(&mut self, fallback: Self);
}

#[cfg(test)]
use mockall::automock;

/// Contains the configuration for a TSN/DetNet application
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, ReplaceNoneOptions)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// Logical interface for the application to bind to (usually a VLAN interface like eth0.2)
    pub logical_interface: Option<String>,

    /// Physical interface corresponding to the logical interface
    pub physical_interface: Option<String>,

    /// Reference time period for traffic specification
    #[serde(default)]
    pub period_ns: Option<u32>,

    /// Time slot offset within period
    ///
    /// It COULD be calculated locally if latency and jitter are not relevant,
    /// otherwise a network-wide calculation (central or decentral) is required
    /// so that packets can optimally directly be forwarded WITHIN the period.
    #[serde(default)]
    pub offset_ns: Option<u32>,

    /// Used to calculate length of the time slot
    #[serde(default)]
    pub size_bytes: Option<u32>,

    /// Destination MAC address
    #[serde(default, with = "serialize_mac_address")]
    pub destination_address: Option<MacAddress>,

    /// VLAN-Identifier
    #[serde(default)]
    pub vid: Option<u16>, // actually 12 bit

    /// Priority Code Point
    #[serde(default)]
    pub pcp: Option<u8>, // actually 3 bit

    /// IP addresses and prefix lengths of the logical interface
    pub addresses: Option<Vec<(IpAddr, u8)>>,

    /// Allow only processes within this cgroup to generate traffic for this app
    pub cgroup: Option<PathBuf>,
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
