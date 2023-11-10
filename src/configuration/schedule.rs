// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Contains the configuration for a Qbv/TAPRIO schedule
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub number_of_traffic_classes: u8,
    pub priority_map: [u8; 8],
    pub basetime_ns: u64, // TODO type?
    pub control_list: Vec<GateControlEntry>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct GateControlEntry {
    pub operation_name: String, // TODO enum!
    pub time_interval_value_ns: u32,
    pub gate_states_value: u8,
}

/// Defines how to request the configuration
#[cfg_attr(test, automock)]
pub trait ScheduleConfiguration {
    fn get_schedule(&mut self, interface_name: &str) -> Result<Schedule>;
}
