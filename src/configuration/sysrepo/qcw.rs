// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Parser for a Qcw YANG model

use crate::configuration;
use anyhow::{anyhow, Result};
use yang2::data::{Data, DataNodeRef, DataTree};

use crate::configuration::schedule::{GateControlEntry, Schedule};
use crate::configuration::sysrepo::helper::{FromDataValue, GetValueForXPath, SysrepoReader};

/// Reads configuration from sysrepo
pub struct SysrepoScheduleConfiguration {
    reader: SysrepoReader,
}

impl SysrepoScheduleConfiguration {
    /// Create a new `SysrepoConfiguration` and connect to `sysrepo`
    ///
    /// # Errors
    ///
    /// Will return `Err` if no proper connection can be set up to Sysrepo,
    /// usually because the service is not running.
    pub fn new() -> Result<Self> {
        Ok(Self {
            reader: SysrepoReader::new()?,
        })
    }
}

impl configuration::schedule::ScheduleConfiguration for SysrepoScheduleConfiguration {
    fn get_schedule(&mut self, interface_name: &str) -> Result<Schedule> {
        let tree = self.reader.get_config("/interfaces")?;
        let interfaces = tree.find_xpath("/interfaces/interface")?;
        for interface in interfaces {
            let name: String = interface.get_value_for_xpath("name")?;
            if name == interface_name {
                return parse_schedule(
                    interface
                        .find_xpath("ieee802-dot1q-bridge:bridge-port")?
                        .next()
                        .ok_or(anyhow!("bridge-port section not found for interface"))?,
                    // TODO better interface for single element?
                );
            }
        }

        Err(anyhow!("Interface not found in configuration"))
    }
}

fn parse_schedule(tree: DataNodeRef) -> Result<Schedule> {
    let tc_table = tree
        .find_xpath("traffic-class/traffic-class-table")?
        .next()
        .ok_or(anyhow!("traffic-class-table not found"))?;
    let priority_map: [u8; 8] = [
        tc_table.get_value_for_xpath("priority0")?,
        tc_table.get_value_for_xpath("priority1")?,
        tc_table.get_value_for_xpath("priority2")?,
        tc_table.get_value_for_xpath("priority3")?,
        tc_table.get_value_for_xpath("priority4")?,
        tc_table.get_value_for_xpath("priority5")?,
        tc_table.get_value_for_xpath("priority6")?,
        tc_table.get_value_for_xpath("priority7")?,
    ];

    let gates = tree
        .find_xpath("ieee802-dot1q-sched-bridge:gate-parameter-table")?
        .next()
        .ok_or(anyhow!("gate-parameter-table not found"))?;
    let mut basetime: u64 = gates.get_value_for_xpath("admin-base-time/seconds")?;
    basetime *= 1000000000;
    basetime += gates.get_value_for_xpath::<u32>("admin-base-time/nanoseconds")? as u64;

    let entries = gates.find_xpath("admin-control-list/gate-control-entry")?;

    // TODO check if index matches!
    let control_list: Vec<GateControlEntry> = entries
        .map(|entry| {
            Ok(GateControlEntry {
                operation_name: entry.get_value_for_xpath("operation-name")?,
                time_interval_value_ns: entry.get_value_for_xpath("time-interval-value")?,
                gate_states_value: entry.get_value_for_xpath("gate-states-value")?,
            })
        })
        .collect::<Result<Vec<GateControlEntry>>>()?;

    Ok(Schedule {
        number_of_traffic_classes: tc_table.get_value_for_xpath("number-of-traffic-classes")?,
        priority_map,
        basetime_ns: basetime,
        control_list,
    })

    /*
    pub struct Schedule {
        pub number_of_traffic_classes: u8,
        pub priority_map: [u8:8];
        pub basetime_ns: u64; // TODO type?
        pub control_list: Vec<GateControlEntry>;
    }

    #[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
    pub struct GateControlEntry {
        pub operation_name: String; // TODO enum!
        pub time_interval_value_ns: u64; // TODO type?
        pub gate_states_value: u8;
    }
         */

    // TODO validate cycle time, currently automatically in TAPRIO, right?
}
