// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use options_struct_derive::validate_are_some;
use tokio::process::Command;

use crate::configuration::{Interface, Mode};
use crate::queue_setup::QueueSetup;

/// Setup TAPRIO Qdisc
pub struct TaprioSetup;

#[async_trait]
impl QueueSetup for TaprioSetup {
    /// Setup TAPRIO schedule for the given interface
    ///
    /// # Errors
    ///
    /// Will return `Err` if it was not possible to setup the schedule.
    async fn apply_config(&self, interface_name: &str, interface_config: &Interface) -> Result<()> {
        let schedule = interface_config.schedule()?;
        let taprio = interface_config.taprio()?;
        validate_are_some!(
            schedule,
            number_of_traffic_classes,
            priority_map,
            basetime_ns,
            control_list,
        )?;
        validate_are_some!(taprio, mode, queues)?;

        let mut command = Command::new("tc");

        command
            .args([
                "qdisc",
                "replace",
                "dev",
                interface_name,
                "parent",
                "root",
                "taprio",
            ])
            .args(["num_tc", &schedule.number_of_traffic_classes()?.to_string()])
            .arg("map");

        for prio in 0..16 {
            command.arg(schedule.tc_for_priority(prio)?.to_string());
        }

        command.arg("queues");

        for (count, offset) in &taprio.queue_mapping_as_pairs()? {
            command.arg(format!("{count}@{offset}"));
        }

        command.args(["base-time", &schedule.basetime_ns()?.to_string()]);

        for &(operation, gate_states, time_interval) in &schedule.gate_control_list()? {
            command.args([
                "sched-entry",
                &operation.to_string(),
                &gate_states.to_string(),
                &time_interval.to_string(),
            ]);
        }

        command.args(["flags", &taprio.mode()?.flags().to_string()]);

        if let Some(clock_id) = taprio.clock {
            command.args(["clockid", &clock_id.to_string()]);
        } else if taprio.mode()? != &Mode::FullOffload {
            return Err(anyhow!(
                "clock parameter is mandatory unless full offload mode is configured"
            ));
        }

        if let Some(txtime_delay) = taprio.txtime_delay {
            command.args(["txtime-delay", &txtime_delay.to_string()]);
        }

        let output = command
            .output()
            .await
            .context("Failed to execute tc command for setting up TAPRIO qdisc")?;

        let stdout = String::from_utf8(output.stdout).context("Invalid UTF-8 sequence")?;

        if !output.status.success() {
            return Err(anyhow!(
                "Setting up TAPRIO qdisc failed with status: {}, {}",
                output.status,
                stdout
            ));
        }

        Ok(())
    }
}
