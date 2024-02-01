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
