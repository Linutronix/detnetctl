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
//! let config = yaml_config.get_ethernet_config("app0")?;
//! # Ok::<(), anyhow::Error>(())
//! ```
use anyhow::Result;
use eui48::MacAddress;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use mockall::automock;

/// Contains the configuration for a TSN-capable Ethernet layer
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct EthernetConfig {
    /// Logical interface for the application to bind to (usually a VLAN interface like eth0.2)
    pub logical_interface: String,

    /// Physical interface corresponding to the logical interface
    pub physical_interface: String,

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
}

mod serialize_mac_address {
    use eui48::MacAddress;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(addr: &Option<MacAddress>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match addr {
            Some(a) => a.to_hex_string(),
            None => "".to_string(),
        };
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<MacAddress>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.is_empty() {
            false => MacAddress::parse_str(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            true => Ok(None),
        }
    }
}

/// Defines how to request the configuration
#[cfg_attr(test, automock)]
pub trait Configuration {
    /// Get the configuration for a given app_name
    fn get_ethernet_config(&mut self, app_name: &str) -> Result<EthernetConfig>;
}

mod yaml;
pub use yaml::YAMLConfiguration;
