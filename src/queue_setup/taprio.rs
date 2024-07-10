// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use log::warn;
use netlink_packet_core::ExtendedAckAttribute;
use nix::errno;
use num_traits::ToPrimitive;
use options_struct_derive::validate_are_some;
use rtnetlink::Error::NetlinkError;
use std::process::Command;

use crate::configuration::{Interface, Mode, Schedule, TaprioConfig};
use crate::interface_setup::NetlinkSetup;
use crate::queue_setup::QueueSetup;

/// Setup TAPRIO Qdisc
pub struct TaprioSetup;

#[async_trait]
impl QueueSetup for TaprioSetup {
    /// Setup TAPRIO schedule for the given interface via netlink
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

        let (connection, handle, _) = rtnetlink::new_connection()?;

        tokio::spawn(connection);

        let idx = NetlinkSetup::get_interface_index(interface_name, &handle)
            .await
            .ok_or_else(|| anyhow!("no interface {interface_name} found"))?;

        let num_tcs = schedule.number_of_traffic_classes()?;

        let priority_map = (0..16)
            .map(|prio| Ok(*schedule.tc_for_priority(prio)?))
            .collect::<Result<Vec<u8>>>()?;

        let mut req = handle
            .qdisc()
            .replace(idx.try_into()?)
            .root()
            .taprio()
            .flags(taprio.mode()?.flags())
            .num_tc(*num_tcs)
            .priority_map(priority_map)?
            .queues(taprio.queue_mapping_as_pairs()?)?
            .basetime(
                (*schedule.basetime_ns()?)
                    .try_into()
                    .context("cannot convert basetime_ns into i64")?,
            )
            .schedule(schedule.gate_control_list()?)?;

        if let Some(clock_id) = taprio.clock {
            req = req.clockid(
                clock_id
                    .to_u32()
                    .ok_or_else(|| anyhow!("Cannot convert clock ID"))?,
            );
        } else if taprio.mode()? != &Mode::FullOffload {
            return Err(anyhow!(
                "clock parameter is mandatory unless full offload mode is configured"
            ));
        }

        if let Some(txtime_delay) = taprio.txtime_delay {
            req = req.txtime_delay(txtime_delay);
        }

        let result = req.execute().await;

        if let Err(NetlinkError(err)) = result {
            let mut msg = String::new();

            for ext_ack in err.extended_ack {
                if let ExtendedAckAttribute::Msg(m) = ext_ack {
                    msg = m;
                }
            }

            if let Some(code) = err.code {
                let errno = errno::Errno::from_i32((-code).into());
                return Err(anyhow!("{} ({}) {msg}", errno.to_string(), (-code)));
            }

            warn!("{msg}");
        }

        Ok(())
    }
}

impl TaprioSetup {
    /// Assemble tc command for the given schedule and interface.
    /// Usually `setup` is preferred that uses netlink directly.
    ///
    /// # Errors
    ///
    /// Will return `Err` if it was not possible to assemble the tc command.
    pub fn assemble_tc_command(
        interface_name: &str,
        taprio: &TaprioConfig,
        schedule: &Schedule,
    ) -> Result<Command> {
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
            command.arg(&schedule.tc_for_priority(prio)?.to_string());
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
        }

        if let Some(txtime_delay) = taprio.txtime_delay {
            command.args(["txtime-delay", &txtime_delay.to_string()]);
        }

        Ok(command)
    }
}
