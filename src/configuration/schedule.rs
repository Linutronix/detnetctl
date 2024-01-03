// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//

use anyhow::Result;
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(test)]
use mockall::automock;

/// Contains the configuration for a Qbv/TAPRIO schedule
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Schedule {
    /// Number of traffic classes
    pub number_of_traffic_classes: u8,

    /// The traffic class to choose for each priority
    pub priority_map: [u8; 8],

    /// The base time for the schedule
    pub basetime_ns: u64,

    /// The schedule defined as gate control entries
    pub control_list: Vec<GateControlEntry>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct GateControlEntry {
    /// The operation to perform. Currently, only SetGates is supported.
    pub operation: GateOperation,

    /// Time interval in nanoseconds
    pub time_interval_value_ns: u32,

    /// Bit mask to define the corresponding traffic classes matching this gate control entry
    pub gate_states_value: u8,
}

/// The operation to perform for a gate control entry
#[derive(Debug, Clone, FromPrimitive, ToPrimitive, PartialEq, Eq, Copy, Serialize, Deserialize)]
pub enum GateOperation {
    /// Gate is open during this interval
    SetGates = 0,

    /// Gate is open and preemption is disabled during this interval
    SetAndHold = 1,

    /// Gate is open and preemption is enabled during this interval
    SetAndRelease = 2,
}

/// Defines how to request the configuration
#[cfg_attr(test, automock)]
pub trait ScheduleConfiguration {
    /// Get all schedules
    fn get_schedules(&mut self) -> Result<HashMap<String, Schedule>>;

    /// Get the schedule matching the given interface name
    fn get_schedule(&mut self, interface_name: &str) -> Result<Schedule>;
}
