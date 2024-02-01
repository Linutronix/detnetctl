// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Configuration for PCP encoding

use crate::configuration::{FillDefaults, ReplaceNoneOptions};
use anyhow::{anyhow, Result};
use options_struct_derive::{OptionsBuilder, OptionsGetters};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// PCP encoding table
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
pub struct PcpEncodingTable {
    map: Option<BTreeMap<u8, u8>>,
}

impl PcpEncodingTable {
    /// Get PCP the given priority
    ///
    /// # Errors
    ///
    /// Returns error if no PCP is found for the given priority
    pub fn pcp_from_priority(&self, priority: u8) -> Result<&u8> {
        self.map()?
            .get(&priority)
            .ok_or_else(|| anyhow!("No PCP found for priority {priority}"))
    }
}

impl FillDefaults for PcpEncodingTable {
    /// Fill unset fields with defaults.
    /// If map is not set, fall back to mapping all priorities 1:1 to the PCP up to 7.
    fn fill_defaults(&mut self) -> Result<()> {
        if self.map.is_none() {
            self.map = Some((0..8).map(|priority| (priority, priority)).collect());
        }

        Ok(())
    }
}
