// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Configuration for DetNet stack

use crate::configuration::{
    FillDefaults, OutgoingL2, OutgoingL2Builder, ReplaceNoneOptions, StreamIdentification,
    StreamIdentificationBuilder,
};
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
    /// Interfaces where the traffic is incoming
    /// to be sent to service sublayer
    ingress_interfaces: Option<Vec<String>>,

    /// TSN stream identifications for ingress
    /// to be sent to service sublayer
    #[replace_none_options_recursively]
    ingress_identification: Option<StreamIdentification>,

    /// Send via L2 after received from service sublayer
    egress_l2: Option<OutgoingL2>,
}

impl FillDefaults for AppFlow {
    /// Fill unset fields with defaults.
    fn fill_defaults(&mut self) -> Result<()> {
        if self.ingress_identification.is_some() {
            fill_struct_defaults!(self, ingress_identification, StreamIdentificationBuilder);
        }

        if self.egress_l2.is_some() {
            fill_struct_defaults!(self, egress_l2, OutgoingL2Builder);
        }

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
pub struct Flow {
    /// Incoming App flows associated to this DetNet flow
    incoming_app_flows: Option<Vec<AppFlow>>,

    /// Outgoing branches of the service sublayer
    /// towards forwarding sublayer
    outgoing_forwarding: Option<Vec<OutgoingForwarding>>,

    /// Forwarding sublayer incoming
    incoming_forwarding: Option<Vec<IncomingForwarding>>,

    /// Outgoing App flows associated to this DetNet flow
    outgoing_app_flows: Option<Vec<AppFlow>>,
}

impl FillDefaults for Flow {
    /// Fill unset fields with defaults.
    /// Currently, no defaults are available.
    fn fill_defaults(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Configuration of an outgoing service entry and forwarding information
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
pub struct OutgoingForwarding {
    /// Encapsulate in MPLS with this header
    #[replace_none_options_recursively]
    mpls: Option<MplsHeader>,

    /// UDP/IP header for encapsulation
    #[replace_none_options_recursively]
    ip: Option<UdpIpHeader>,

    /// Outgoing L2 configuration
    outgoing_l2: Option<Vec<OutgoingL2>>,
}

impl FillDefaults for OutgoingForwarding {
    /// Fill unset fields with defaults.
    /// If `mpls` is not provided, no MPLS encapsulation will take place.
    /// If `ip` is not provided, no UDP/IP encapsulation will take place.
    fn fill_defaults(&mut self) -> Result<()> {
        if self.mpls.is_some() {
            fill_struct_defaults!(self, mpls, MplsHeaderBuilder);
        }

        if self.ip.is_some() {
            fill_struct_defaults!(self, ip, UdpIpHeaderBuilder);
        }

        if let Some(outgoing_l2s) = &mut self.outgoing_l2 {
            for outgoing_l2 in outgoing_l2s {
                outgoing_l2.fill_defaults()?;
            }
        }

        Ok(())
    }
}

/// Configuration of an incoming service entry and forwarding information
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
pub struct IncomingForwarding {
    /// Interface where the traffic is incoming
    /// to be sent to service sublayer
    incoming_interface: Option<String>,

    /// MPLS label
    mpls_label: Option<u32>, // actually 20 bits

    /// Source port
    udp_source_port: Option<u16>,
}

impl FillDefaults for IncomingForwarding {
    /// Fill unset fields with defaults.
    /// Currently, no defaults are available.
    fn fill_defaults(&mut self) -> Result<()> {
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
