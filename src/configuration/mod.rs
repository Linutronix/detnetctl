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
use std::collections::BTreeMap;
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

    /// TSN stream identification
    stream: Option<StreamIdentification>,

    /// IP addresses and prefix lengths of the logical interface
    addresses: Option<Vec<(IpAddr, u8)>>,

    /// Allow only processes within this cgroup to generate traffic for this app
    cgroup: Option<PathBuf>,

    /// Priority
    /// With the TSN dispatcher, it does not need to be set as `SO_PRIORITY`.
    /// Its purpose is to define the link `app -> priority -> traffic_class -> gate`.
    priority: Option<u8>,
}

impl FillDefaults for AppConfig {
    /// Fill unset fields with defaults.
    /// Only `priority` is set to 0 (best-effort) if not provided.
    fn fill_defaults(&mut self) -> Result<()> {
        if self.priority.is_none() {
            self.priority = Some(0);
        }

        Ok(())
    }
}

/// Stream identification
/// Currently only IEEE 802.1CB-2017 null stream identification is supported
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
pub struct StreamIdentification {
    /// Destination MAC address
    #[serde(default, with = "serialize_mac_address")]
    destination_address: Option<MacAddress>,

    /// VLAN Identifier
    #[serde(default)]
    vid: Option<u16>, // actually 12 bit
}

mod schedule;
pub use schedule::{
    GateControlEntry, GateControlEntryBuilder, GateOperation, Schedule, ScheduleBuilder,
};

mod taprio;
pub use self::taprio::{Clock, Mode, QueueMapping, TaprioConfig, TaprioConfigBuilder};

mod pcp;
pub use self::pcp::{PcpEncodingTable, PcpEncodingTableBuilder};

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
    schedule: Option<Schedule>,

    /// TAPRIO configuration
    /// (excluding the schedule itself)
    taprio: Option<TaprioConfig>,

    /// PCP encoding table
    pcp_encoding: Option<PcpEncodingTable>,
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

        let num_tc = *self.schedule()?.number_of_traffic_classes()?;
        if let Some(taprio) = self.taprio.as_mut() {
            taprio.fill_defaults(num_tc)?;
        } else {
            let mut taprio = TaprioConfigBuilder::new().build();
            taprio.fill_defaults(num_tc)?;
            self.taprio = Some(taprio);
        }

        if let Some(pcp_encoding) = self.pcp_encoding.as_mut() {
            pcp_encoding.fill_defaults()?;
        } else {
            let mut pcp_encoding = PcpEncodingTableBuilder::new().build();
            pcp_encoding.fill_defaults()?;
            self.pcp_encoding = Some(pcp_encoding);
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
    fn get_interface_configs(&mut self) -> Result<BTreeMap<String, TsnInterfaceConfig>>;

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
    fn get_app_configs(&mut self) -> Result<BTreeMap<String, AppConfig>>;

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
