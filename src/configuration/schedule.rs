// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::configuration::{FillDefaults, OptionsBuilder, OptionsGetters, ReplaceNoneOptions};
use anyhow::{anyhow, Result};
use log::{info, warn};
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default priority map (see IEEE 802.1Q-2022 Table 8-5)
/// The mapping 0->1, 1->0 is on purpose (see Annex I)
const DEFAULT_PRIORITY_MAP: [[u8; 8]; 8] = [
    [0, 0, 0, 0, 0, 0, 0, 0], // number_of_traffic_classes 1
    [0, 0, 0, 0, 1, 1, 1, 1], // number_of_traffic_classes 2
    [0, 0, 0, 0, 1, 1, 2, 2], // number_of_traffic_classes 3
    [0, 0, 1, 1, 2, 2, 3, 3], // number_of_traffic_classes 4
    [0, 0, 1, 1, 2, 2, 3, 4], // number_of_traffic_classes 5
    [1, 0, 2, 2, 3, 3, 4, 5], // number_of_traffic_classes 6
    [1, 0, 2, 3, 4, 4, 5, 6], // number_of_traffic_classes 7
    [1, 0, 2, 3, 4, 5, 6, 7], // number_of_traffic_classes 8
];
const DEFAULT_NUM_TCS: u8 = 8;

/// Unspecified priorities are mapped to the same traffic class
/// as priority 0 (best-effort, see IEEE 802.1Q-2022 Annex I).
const BEST_EFFORT_PRIORITY: u8 = 0;

/// Contains the configuration for a Qbv/TAPRIO schedule
#[derive(
    Default,
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
pub struct Schedule {
    /// Number of traffic classes
    number_of_traffic_classes: Option<u8>,

    /// The traffic class to choose for each priority
    priority_map: Option<HashMap<u8, u8>>,

    /// The base time (relative to Unix epoch) in nanoseconds.
    /// If not set, 0 will be used as default and a warning is logged.
    basetime_ns: Option<u64>,

    /// The schedule defined as gate control entries
    control_list: Option<Vec<GateControlEntry>>,
}

/// Configuration for a gate control entry
#[derive(
    Default,
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
pub struct GateControlEntry {
    /// The operation to perform. Currently, only SetGates is supported.
    operation: Option<GateOperation>,

    /// Time interval in nanoseconds
    time_interval_ns: Option<u32>,

    /// The traffic classes this gate control entry shall apply to.
    /// Corresponds to the gate states bitmask.
    traffic_classes: Option<Vec<u8>>,
}

impl GateControlEntry {
    fn operation_char(&self) -> Result<char> {
        match self.operation()? {
            GateOperation::SetGates => Ok('S'),
            _ => Err(anyhow!(
                "Currently, only SetGates (S) operation is supported"
            )),
        }
    }
}

/// The operation to perform for a gate control entry
#[derive(Debug, Clone, FromPrimitive, ToPrimitive, PartialEq, Eq, Copy, Serialize, Deserialize)]
#[allow(clippy::enum_variant_names)] // Names given by standard
pub enum GateOperation {
    /// Gate is open during this interval
    SetGates = 0,

    /// Gate is open and preemption is disabled during this interval
    SetAndHold = 1,

    /// Gate is open and preemption is enabled during this interval
    SetAndRelease = 2,
}

fn invalid_gate_control_list_error() -> Result<()> {
    Err(anyhow!("Not valid gate control list. At least the time intervals and traffic classes need to be provided for them because there is no reasonable default for them."))
}

impl FillDefaults for Schedule {
    /// Fill unset fields with defaults.
    ///
    /// If field `basetime_ns` is not set, 0 is set and a warning is logged.
    ///
    /// `control_list` is required as well as `time_interval_ns` and `traffic_classes`
    /// for each entry. However, `operation` is set to `SetGates` if not provided.
    ///
    /// If field `number_of_traffic_classes` is not set, the maximum of `priority_map` + 1 is taken
    /// or if that is also not provided, 8 (as maximum number supported by IEEE 802.1Q-2022).
    ///
    /// If field `priority_map` is not set or empty, the default is selected according to Table 8-5 of IEEE 802.1Q-2022:
    ///
    /// <table>
    /// <thead>
    ///   <tr>
    ///     <th colspan="2" rowspan="2"></th>
    ///     <th colspan="8">Number of available traffic classes</th>
    ///   </tr>
    ///   <tr>
    ///     <th>1</th>
    ///     <th>2</th>
    ///     <th>3</th>
    ///     <th>4</th>
    ///     <th>5</th>
    ///     <th>6</th>
    ///     <th>7</th>
    ///     <th>8</th>
    ///   </tr>
    /// </thead>
    /// <tbody>
    ///   <tr>
    ///     <td rowspan="8">Priority</td>
    ///     <td>0<br></td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///     <td>1</td>
    ///     <td>1</td>
    ///     <td>1<br></td>
    ///   </tr>
    ///   <tr>
    ///     <td>1</td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///   </tr>
    ///   <tr>
    ///     <td>2</td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///     <td>1</td>
    ///     <td>1</td>
    ///     <td>2</td>
    ///     <td>2</td>
    ///     <td>2</td>
    ///   </tr>
    ///   <tr>
    ///     <td>3</td>
    ///     <td>0</td>
    ///     <td>0</td>
    ///     <td>0<br></td>
    ///     <td>1</td>
    ///     <td>1</td>
    ///     <td>2</td>
    ///     <td>3</td>
    ///     <td>3</td>
    ///   </tr>
    ///   <tr>
    ///     <td>4</td>
    ///     <td>0</td>
    ///     <td>1</td>
    ///     <td>1</td>
    ///     <td>2</td>
    ///     <td>2</td>
    ///     <td>3</td>
    ///     <td>4</td>
    ///     <td>4</td>
    ///   </tr>
    ///   <tr>
    ///     <td>5</td>
    ///     <td>0</td>
    ///     <td>1</td>
    ///     <td>1</td>
    ///     <td>2</td>
    ///     <td>2</td>
    ///     <td>3</td>
    ///     <td>4</td>
    ///     <td>5</td>
    ///   </tr>
    ///   <tr>
    ///     <td>6</td>
    ///     <td>0</td>
    ///     <td>1</td>
    ///     <td>2</td>
    ///     <td>3</td>
    ///     <td>3</td>
    ///     <td>4</td>
    ///     <td>5</td>
    ///     <td>6</td>
    ///   </tr>
    ///   <tr>
    ///     <td>7</td>
    ///     <td>0</td>
    ///     <td>1</td>
    ///     <td>2</td>
    ///     <td>3</td>
    ///     <td>4</td>
    ///     <td>5</td>
    ///     <td>6</td>
    ///     <td>7</td>
    ///   </tr>
    /// </tbody>
    /// </table>
    ///
    /// # Errors
    ///
    /// Returns an error if no valid configuration could be calculated,
    /// e.g. if the number of traffic classes is larger than 8, because that is not
    /// supported by IEEE 802.1Q-2022 at the moment.
    fn fill_defaults(&mut self) -> Result<()> {
        // --- basetime_ns ---
        if self.basetime_ns.is_none() {
            // basetime 0 is a reasonable default if you do not care about
            // absolute positioning of the schedule in time and thus especially
            // convenient for testing/demo purposes. Still warn if it was a mistake.
            warn!("basetime not specified. Assuming 0.");
            self.basetime_ns = Some(0);
        }

        // --- control_list ---
        let Some(control_list) = self.control_list.as_mut() else {
            return invalid_gate_control_list_error();
        };

        if control_list.is_empty() {
            return invalid_gate_control_list_error();
        }

        for entry in control_list {
            entry.fill_defaults()?;
        }

        // --- number_of_traffic_classes ---
        if let Some(num_tc) = self.number_of_traffic_classes {
            if num_tc > 8 {
                return Err(anyhow!("IEEE 802.1Q-2022 only supports up to 8 traffic classes, but number_of_traffic_classes is {num_tc}."));
            }
        } else if let Some(priority_map) = self.priority_map.as_ref() {
            // Maximum in priority_map + 1 should be a resonable default.
            // If nothing is in priority_map, assume one traffic class.
            let num_tc = priority_map.values().max().unwrap_or(&0) + 1;

            if num_tc > 8 {
                return Err(anyhow!("IEEE 802.1Q-2022 only supports up to 8 traffic classes, but maximum traffic class + 1 in priority_map is {num_tc}."));
            }

            // I do not see any negative side effects, so do not warn, but still inform.
            info!("number_of_traffic_classes not provided. Using {num_tc} since it is the maximum + 1 of priority_map");
            self.number_of_traffic_classes = Some(num_tc);
        } else {
            info!(
                "number_of_traffic_classes not provided. Using {} as default",
                DEFAULT_NUM_TCS
            );

            self.number_of_traffic_classes = Some(DEFAULT_NUM_TCS);
        }

        // --- priority_map ---
        let num_tc = self.number_of_traffic_classes()?;

        let default_priority_map = || {
            let priority_map = DEFAULT_PRIORITY_MAP
                .get(usize::from(num_tc - 1))
                .ok_or_else(|| {
                    anyhow!("Invalid number of traffic classes when selecting default priority map")
                })?;

            priority_map
                .iter()
                .enumerate()
                .map(|(i, v)| Ok((u8::try_from(i)?, *v)))
                .collect::<Result<HashMap<u8, u8>>>()
        };

        if let Some(priority_map) = &self.priority_map {
            if priority_map.is_empty() {
                self.priority_map = Some(default_priority_map()?);
            } else {
                for (priority, tc) in priority_map {
                    if tc >= num_tc {
                        return Err(anyhow!("Traffic class {tc} for priority {priority} is larger than or equal to number_of_traffic_classes {num_tc}."));
                    }
                }
            }
        } else {
            self.priority_map = Some(default_priority_map()?);
        }

        Ok(())
    }
}

impl FillDefaults for GateControlEntry {
    /// Fill unset fields with defaults.
    ///
    /// Sets `SetGates` if `operation` is not provided and checks if both other fields are
    /// available.
    ///
    /// # Errors
    ///
    /// `traffic_classes` and `time_interval_ns` is required. Otherwise return an error.
    fn fill_defaults(&mut self) -> Result<()> {
        if self.traffic_classes.is_none() || self.time_interval_ns.is_none() {
            invalid_gate_control_list_error()?;
        }

        if self.operation.is_none() {
            self.operation = Some(GateOperation::SetGates);
        }

        Ok(())
    }
}

impl Schedule {
    /// Return the map of priorities to traffic classes
    ///
    /// # Errors
    ///
    /// Return error if `priority_map` is not set. For unconfigured priority, the default traffic
    /// class 1 is returned.
    pub fn tc_for_priority(&self, priority: u8) -> Result<&u8> {
        let tc = self.priority_map()?.get(&priority);

        // fall back to best effort if priority is not defined in priority map
        tc.map_or_else(
            || self.priority_map()?.get(&BEST_EFFORT_PRIORITY)
               .ok_or_else(|| anyhow!("Requested priority {priority} not found in priority_map. Fallback priority {BEST_EFFORT_PRIORITY} also not found.")),
            Ok,
        )
    }

    /// Return the gate control list as vector of tuples
    /// (operation character, gate states value, time interval).
    ///
    /// # Errors
    ///
    /// Returns an error if `control_list` is invalid.
    pub fn gate_control_list(&self) -> Result<Vec<(char, u32, u32)>> {
        self.control_list()?
            .iter()
            .map(|entry| {
                Ok((
                    entry.operation_char()?,
                    entry
                        .traffic_classes()?
                        .iter()
                        .try_fold(0_u8, |acc, tc| -> Result<u8> {
                            // set all bits corresponding to the tcs in the vector
                            Ok(acc | Self::bitmask_from_tc(*tc)?)
                        })?
                        .into(),
                    *entry.time_interval_ns()?,
                ))
            })
            .collect::<Result<Vec<(char, u32, u32)>>>()
    }

    fn bitmask_from_tc(tc: u8) -> Result<u8> {
        1_u8.checked_shl(tc.into())
            .ok_or_else(|| anyhow!("Invalid traffic class {tc}"))
    }
}
