// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Configuration for DetNet stack

use crate::configuration::{FillDefaults, ReplaceNoneOptions, StreamIdentification};
use anyhow::{anyhow, Result};
use options_struct_derive::{OptionsBuilder, OptionsGetters};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Configuration of a DetNet App Flow
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
pub struct AppFlow {
    /// Interface for the application to bind to (usually a VLAN interface like eth0.2)
    ingress_interface: Option<String>,

    /// IP addresses and prefix lengths to be configured for the ingress interface
    addresses: Option<Vec<(IpAddr, u8)>>,

    /// TSN stream identification for ingress
    #[replace_none_options_recursively]
    stream: Option<StreamIdentification>,
}

impl FillDefaults for AppFlow {
    /// Fill unset fields with defaults.
    /// Currently, no defaults are available.
    fn fill_defaults(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Configuration of a DetNet Service Sublayer
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
pub struct ServiceSublayer {
    #[replace_none_options_recursively]
    mpls: Option<MplsHeader>,
}

impl FillDefaults for ServiceSublayer {
    /// Fill unset fields with defaults.
    /// Currently, no defaults are available.
    /// If `mpls` is not provided, no MPLS encapsulation will take place.
    fn fill_defaults(&mut self) -> Result<()> {
        if self.mpls.is_some() {
            fill_struct_defaults!(self, mpls, MplsHeaderBuilder);
        }

        Ok(())
    }
}

/// Configuration of a MPLS header
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
pub struct MplsHeader {
    /// MPLS label
    label: Option<u32>, // actually 20 bits

    /// MPLS traffic class (aka EXP before RFC 5462)
    tc: Option<u8>, // actually 3 bits

    /// MPLS TTL (time to live)
    ttl: Option<u8>,
}

impl FillDefaults for MplsHeader {
    /// Fill unset fields with defaults.
    /// `tc` is set to 0 if not provided.
    /// `ttl` is set to 255 if not provided.
    fn fill_defaults(&mut self) -> Result<()> {
        if self.tc.is_none() {
            self.tc = Some(0);
        }

        if self.ttl.is_none() {
            self.ttl = Some(255);
        }

        Ok(())
    }
}

/// Configuration of a DetNet Forwarding Sublayer
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
pub struct ForwardingSublayer {
    /// UDP/IP header for encapsulation
    #[replace_none_options_recursively]
    ip: Option<UdpIpHeader>,
}

impl FillDefaults for ForwardingSublayer {
    /// Fill unset fields with defaults.
    /// Currently, no defaults are available.
    /// If `ip` is not provided, no UDP/IP encapsulation will take place.
    fn fill_defaults(&mut self) -> Result<()> {
        if self.ip.is_some() {
            fill_struct_defaults!(self, ip, UdpIpHeaderBuilder);
        }

        Ok(())
    }
}

/// Configuration of an IP plus UDP header used for encapsulation
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
pub struct UdpIpHeader {
    /// Source IP address
    source: Option<IpAddr>,

    /// Destination IP address
    destination: Option<IpAddr>,

    /// Protocol next header
    /// Should usually be 17, since only UDP encapsulation is supported at the moment
    protocol_next_header: Option<u8>,

    /// DSCP
    dscp: Option<u8>, // actually 6 bits

    /// Flow label
    flow: Option<u32>, // actually 20 bits

    /// Source port
    source_port: Option<u16>,

    /// Destination port
    /// Should usually be 6635 to indicate a MPLS packet as payload (RFC 7510)
    destination_port: Option<u16>,
}

impl FillDefaults for UdpIpHeader {
    /// Fill unset fields with defaults.
    /// `protocol_next_header` is set to 17 if not provided.
    /// `dscp` is set to 0 if not provided.
    /// `flow` is set to 0 if not provided.
    /// `dest_port` is set to 6635 if not provided.
    fn fill_defaults(&mut self) -> Result<()> {
        if self.protocol_next_header.is_none() {
            self.protocol_next_header = Some(17);
        }

        if self.dscp.is_none() {
            self.dscp = Some(0);
        }

        if self.flow.is_none() {
            self.flow = Some(0);
        }

        if self.destination_port.is_none() {
            self.destination_port = Some(6635);
        }

        Ok(())
    }
}
