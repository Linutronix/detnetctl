// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Result};
use clap::ValueEnum;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::ToPrimitive;
use std::fmt;
use std::process::Command;
use nix::libc::{CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_TAI};
use nix::errno;
use rtnetlink::Error::NetlinkError;
use netlink_packet_core::ExtendedAckAttribute;
use log::warn;

use crate::configuration::{GateOperation, Schedule};
use crate::interface_setup::NetlinkSetup;

/// The TAPRIO offload mode to apply
#[derive(ValueEnum, Debug, Clone, PartialEq, Eq, Copy)]
#[clap(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Mode {
    /// Emulate TAPRIO fully in software without need for hardware support
    Software,

    /// Emulate TAPRIO in software, but send the packets with TX timestamps to the NIC
    /// Requires NIC support for tx-time.
    TxTimeAssist,

    /// Fully offload TAPRIO to the NIC. Requires respective support.
    FullOffload,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Software => write!(f, "SOFTWARE"),
            Self::TxTimeAssist => write!(f, "TX_TIME_ASSIST"),
            Self::FullOffload => write!(f, "FULL_OFFLOAD"),
        }
    }
}

impl Mode {
    /// Get the flags in the bitmask for each mode
    #[must_use]
    pub const fn flags(self) -> u32 {
        match self {
            Self::Software => 0x0,
            Self::TxTimeAssist => 0x1,
            Self::FullOffload => 0x2,
        }
    }
}

/// The ID for the clock to use for TAPRIO
#[derive(ValueEnum, Debug, Clone, FromPrimitive, ToPrimitive, PartialEq, Eq, Copy)]
#[clap(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(clippy::as_conversions)] // as is safe here and there is no reasonable alternative
pub enum ClockId {
    /// Clock corresponding to the International Atomic Time (TAI) if available. Not corrected by leap seconds.
    Tai = CLOCK_TAI as isize,

    /// The best effort estimate of UTC that is always available.
    Realtime = CLOCK_REALTIME as isize,

    /// Clock that cannot be set and represents monotonic time since some unspecified starting point.
    Monotonic = CLOCK_MONOTONIC as isize,

    /// Identical to CLOCK_MONOTONIC, except it also includes any time that the system is suspended.
    Boottime = CLOCK_BOOTTIME as isize,
}

impl fmt::Display for ClockId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Tai => write!(f, "CLOCK_TAI"),
            Self::Realtime => write!(f, "CLOCK_REALTIME"),
            Self::Boottime => write!(f, "CLOCK_BOOTTIME"),
            Self::Monotonic => write!(f, "CLOCK_MONOTONIC"),
        }
    }
}

/// Setup TAPRIO via netlink
pub struct TaprioSetup {
    /// The offload mode
    pub mode: Mode,

    /// The clock to use
    pub clock_id: Option<ClockId>,

    /// The maximum time a packet might take to reach the network card from the taprio qdisc.
    /// Only used for TxTimeAssist mode.
    pub txtime_delay: Option<u32>,

    /// Use this traffic class for all unspecified priorities
    pub tc_fallback: u8,

    /// Count and offset of queue range for each traffic class in the format count@offset.
    /// If empty, perform a one-to-one mapping of traffic classes and queues (1@0 1@1 ... 1@<num_tc-1>).
    pub queues: Vec<String>,
}

impl TaprioSetup {
    fn queues(&self, num_tc: u8) -> Result<Vec<(u16, u16)>> {
        if self.queues.is_empty() {
            Ok((0..num_tc).map(|i| (1, i.into())).collect())
        } else {
            self.queues
                .iter()
                .map(|pair| {
                    let parts: Vec<&str> = pair.split('@').collect();
                    let count = parts
                        .first()
                        .ok_or_else(|| anyhow!("count missing in queue definition"))?
                        .parse::<u16>()?;
                    let offset = parts
                        .get(1)
                        .ok_or_else(|| anyhow!("offset missing in queue definition"))?
                        .parse::<u16>()?;
                    Ok((count, offset))
                })
                .collect()
        }
    }

    fn priority_map(&self, schedule: &Schedule) -> Vec<u8> {
        let mut priority_map = schedule.priority_map.to_vec();
        priority_map.resize(16, self.tc_fallback);
        priority_map
    }

    fn operation_char(operation: GateOperation) -> Result<char> {
        if operation == GateOperation::SetGates {
            Ok('S')
        } else {
            Err(anyhow!(
                "Currently, only SetGates (S) operation is supported"
            ))
        }
    }

    /// Setup TAPRIO schedule for the given interface via netlink
    ///
    /// # Errors
    ///
    /// Will return `Err` if it was not possible to setup the schedule.
    pub async fn setup(&self, interface_name: &str, schedule: &Schedule) -> Result<()> {
        let (connection, handle, _) = rtnetlink::new_connection()?;

        tokio::spawn(connection);

        let idx = NetlinkSetup::get_interface_index(interface_name, &handle).await?;

        let mut req = handle
            .qdisc()
            .replace(idx.try_into()?)
            .root()
            .taprio()
            .flags(self.mode.flags())
            .num_tc(schedule.number_of_traffic_classes)
            .priority_map(self.priority_map(schedule))?
            .queues(self.queues(schedule.number_of_traffic_classes)?)?
            .basetime(schedule.basetime_ns.try_into()?)
            .schedule(
                schedule
                    .control_list
                    .iter()
                    .map(|entry| {
                        Ok((
                            Self::operation_char(entry.operation)?,
                            entry.gate_states_value.into(),
                            entry.time_interval_value_ns,
                        ))
                    })
                    .collect::<Result<Vec<(char, u32, u32)>>>()?,
            )?;

        if let Some(clock_id) = self.clock_id {
            req = req.clockid(
                clock_id
                    .to_u32()
                    .ok_or_else(|| anyhow!("Cannot convert clock ID"))?,
            );
        }

        if let Some(txtime_delay) = self.txtime_delay {
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

    /// Assemble tc command for the given schedule and interface.
    /// Usually `setup` is preferred that uses netlink directly.
    ///
    /// # Errors
    ///
    /// Will return `Err` if it was not possible to assemble the tc command.
    pub fn assemble_tc_command(
        &self,
        interface_name: &str,
        schedule: &Schedule,
    ) -> Result<Command> {
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
            .args(["num_tc", &schedule.number_of_traffic_classes.to_string()])
            .arg("map");

        for prio in &self.priority_map(schedule) {
            command.arg(&prio.to_string());
        }

        command.arg("queues");

        for (count, offset) in &self.queues(schedule.number_of_traffic_classes)? {
            command.arg(format!("{count}@{offset}"));
        }

        command.args(["base-time", &schedule.basetime_ns.to_string()]);

        for entry in &schedule.control_list {
            command.args([
                "sched-entry",
                &Self::operation_char(entry.operation)?.to_string(),
                &entry.gate_states_value.to_string(),
                &entry.time_interval_value_ns.to_string(),
            ]);
        }

        command.args(["flags", &self.mode.flags().to_string()]);

        if let Some(clock_id) = self.clock_id {
            command.args(["clockid", &clock_id.to_string()]);
        }

        if let Some(txtime_delay) = self.txtime_delay {
            command.args(["txtime-delay", &txtime_delay.to_string()]);
        }

        Ok(command)
    }
}
