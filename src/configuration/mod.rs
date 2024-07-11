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
//! let config = yaml_config.get_unbridged_app("app0")?;
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! With sysrepo configuration (for NETCONF integration):
#![cfg_attr(not(feature = "sysrepo"), doc = "```ignore")]
#![cfg_attr(feature = "sysrepo", doc = "```no_run")]
//! use detnetctl::configuration::{Configuration, SysrepoConfiguration};
//! let mut sysrepo_config = SysrepoConfiguration::new()?;
//! let config = sysrepo_config.get_stream("stream0");
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

macro_rules! fill_struct_defaults {
    ($parent:ident, $field:ident, $builder:ident) => {
        if let Some(val) = $parent.$field.as_mut() {
            val.fill_defaults()?;
        } else {
            let mut $field = $builder::new().build();
            $field.fill_defaults()?;
            $parent.$field = Some($field);
        }
    };
}

#[cfg(test)]
use mockall::automock;

/// Contains the configuration for an unbridged TSN/DetNet application
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
pub struct UnbridgedApp {
    /// Interface for the application to bind to (usually a VLAN interface like eth0.2)
    bind_interface: Option<String>,

    /// Physical interface as parent of the bind interface
    physical_interface: Option<String>,

    /// TSN stream identification
    #[replace_none_options_recursively]
    stream: Option<StreamIdentification>,

    /// Allow only processes within this cgroup to generate traffic for this app
    cgroup: Option<PathBuf>,

    /// Priority
    /// With the TSN dispatcher, it does not need to be set as `SO_PRIORITY`.
    /// Its purpose is to define the link `app -> priority -> traffic_class -> gate`.
    priority: Option<u8>,
}

impl FillDefaults for UnbridgedApp {
    /// Fill unset fields with defaults.
    /// Only `priority` is set to 0 (best-effort) if not provided.
    fn fill_defaults(&mut self) -> Result<()> {
        if self.priority.is_none() {
            self.priority = Some(0);
        }

        Ok(())
    }
}

/// Contains the configuration for a bridged TSN/DetNet application
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
pub struct BridgedApp {
    /// Interface for the application to bind to (usually a VLAN interface like veth0.2)
    bind_interface: Option<String>,

    /// Virtual interface as parent of the bind interface (e.g. veth0)
    virtual_interface_app: Option<String>,

    /// Network namespace on app side
    netns_app: Option<String>,

    /// Virtual interface towards the bridge (e.g. veth1) in default host network namespace
    virtual_interface_bridge: Option<String>,
}

impl FillDefaults for BridgedApp {
    /// Fill unset fields with defaults.
    fn fill_defaults(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Contains the configuration for a TSN Stream
/// If used in DetNet context, this matches a tsn-app-flow
/// If packets arrive with R-Tag,
/// frame eleminiation (according to IEEE 802.1CB)
/// is performed and the R-Tag is removed.
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
pub struct Stream {
    /// Interfaces where the traffic is incoming
    incoming_interfaces: Option<Vec<String>>,

    /// TSN stream identifications for ingress
    identifications: Option<Vec<StreamIdentification>>,

    /// Directly send over L2 without DetNet handling
    /// If more than one element is in the vector,
    /// frame replication (according to IEEE 802.1CB)
    /// is performed and an R-Tag is added.
    outgoing_l2: Option<Vec<OutgoingL2>>,
}

impl FillDefaults for Stream {
    /// Fill unset fields with defaults.
    /// For `identification` and `outgoing_l2`, see the respective structs.
    fn fill_defaults(&mut self) -> Result<()> {
        if let Some(identifications) = &mut self.identifications {
            for identification in identifications {
                identification.fill_defaults()?;
            }
        }

        if let Some(vecl2) = &mut self.outgoing_l2 {
            for l2 in vecl2 {
                l2.fill_defaults()?;
            }
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

impl FillDefaults for StreamIdentification {
    /// Fill unset fields with defaults.
    /// Nothing set at the moment.
    fn fill_defaults(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Configuration for the egress via L2
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
pub struct OutgoingL2 {
    /// Outgoing interface. Link to the respective TSN interface configuration.
    outgoing_interface: Option<String>,

    /// Source MAC address
    /// If provided, sets the source address of the outermost Ethernet header
    #[serde(default, with = "serialize_mac_address")]
    source: Option<MacAddress>,

    /// Destination MAC address
    /// If provided, sets the destination address of the outermost Ethernet header
    #[serde(default, with = "serialize_mac_address")]
    destination: Option<MacAddress>,

    /// VLAN Identifier
    /// If provided, sets the VLAN tag of the outermost Ethernet header
    #[serde(default)]
    vid: Option<u16>, // actually 12 bit

    /// Priority Code Point
    /// If provided, sets the PCP field of the outermost Ethernet header
    #[serde(default)]
    pcp: Option<u8>, // actually 3 bit

    /// Ether Type
    /// If provided, sets the Ether Type of the outermost Ethernet header
    #[serde(default)]
    ether_type: Option<u16>,
}

impl FillDefaults for OutgoingL2 {
    /// Fill unset fields with defaults.
    fn fill_defaults(&mut self) -> Result<()> {
        Ok(())
    }
}

mod schedule;
pub use schedule::{
    GateControlEntry, GateControlEntryBuilder, GateOperation, Schedule, ScheduleBuilder,
};

mod taprio;
pub use self::taprio::{Clock, Mode, QueueMapping, TaprioConfig, TaprioConfigBuilder};

mod pcp;
pub use self::pcp::{PcpEncodingTable, PcpEncodingTableBuilder};

/// Contains the configuration for an interface
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
pub struct Interface {
    /// Qbv schedule
    schedule: Option<Schedule>,

    /// TAPRIO configuration
    /// (excluding the schedule itself)
    taprio: Option<TaprioConfig>,

    /// PCP encoding table
    pcp_encoding: Option<PcpEncodingTable>,

    /// IP addresses and prefix lengths to configure
    addresses: Option<Vec<(IpAddr, u8)>>,
}

impl FillDefaults for Interface {
    fn fill_defaults(&mut self) -> Result<()> {
        if let Some(schedule) = self.schedule.as_mut() {
            schedule.fill_defaults()?;

            let num_tc = *self.schedule()?.number_of_traffic_classes()?;
            if let Some(taprio) = self.taprio.as_mut() {
                taprio.fill_defaults(num_tc)?;
            } else {
                let mut taprio = TaprioConfigBuilder::new().build();
                taprio.fill_defaults(num_tc)?;
                self.taprio = Some(taprio);
            }
        } // else keep schedule and taprio as None if not provided!

        fill_struct_defaults!(self, pcp_encoding, PcpEncodingTableBuilder);

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
    fn get_interfaces(&mut self) -> Result<BTreeMap<String, Interface>>;

    /// Get configuration for the given interface
    ///
    /// # Errors
    ///
    /// Will return `Err` if there is a general problem reading the configuration.
    /// If no interface was found for that `interface_name`, Ok(None) is returned.
    fn get_interface(&mut self, interface_name: &str) -> Result<Option<Interface>>;

    /// Get the configuration for a given unbridged `app_name`
    ///
    /// # Errors
    ///
    /// Will return `Err` if there is a general problem reading the configuration.
    /// If no `UnbridgedApp` is found for the name, Ok(None) is returned.
    fn get_unbridged_app(&mut self, app_name: &str) -> Result<Option<UnbridgedApp>>;

    /// Get the configuration for all provided unbridged apps
    ///
    /// # Errors
    ///
    /// Will return `Err` if there is a general problem reading the configuration.
    fn get_unbridged_apps(&mut self) -> Result<BTreeMap<String, UnbridgedApp>>;

    /// Get the configuration for a given bridged `app_name`
    ///
    /// # Errors
    ///
    /// Will return `Err` if there is a general problem reading the configuration.
    /// If no `BridgedApp` is found for the name, Ok(None) is returned.
    fn get_bridged_app(&mut self, app_name: &str) -> Result<Option<BridgedApp>>;

    /// Get the configuration for all provided bridged apps
    ///
    /// # Errors
    ///
    /// Will return `Err` if there is a general problem reading the configuration.
    fn get_bridged_apps(&mut self) -> Result<BTreeMap<String, BridgedApp>>;

    /// Get the configuration for a given `stream_name`
    ///
    /// # Errors
    ///
    /// Will return `Err` if there is a general problem reading the configuration.
    /// If no `AppConfig` is found for the name, Ok(None) is returned.
    fn get_stream(&mut self, stream_name: &str) -> Result<Option<Stream>>;

    /// Get the configuration for all provided streams
    ///
    /// # Errors
    ///
    /// Will return `Err` if there is a general problem reading the configuration.
    fn get_streams(&mut self) -> Result<BTreeMap<String, Stream>>;

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
