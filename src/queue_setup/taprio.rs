// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Result};
use clap::ValueEnum;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::ToPrimitive;
use std::fmt;
use std::process::Command;

use crate::configuration::{GateOperation, Schedule};
use crate::interface_setup::NetlinkSetup;
use nix::libc::{CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_TAI};
//use nix::sys::socket::setsockopt;
use nix::libc;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use core::mem;
use rtnetlink::Error::NetlinkError;

#[derive(ValueEnum, Debug, Clone, PartialEq, Copy)]
#[clap(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Mode {
    Software,
    TxTimeAssist,
    FullOffload,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Mode::Software => write!(f, "SOFTWARE"),
            Mode::TxTimeAssist => write!(f, "TX_TIME_ASSIST"),
            Mode::FullOffload => write!(f, "FULL_OFFLOAD"),
        }
    }
}

impl Mode {
    pub fn flags(&self) -> u32 {
        match self {
            Mode::Software => 0x0,
            Mode::TxTimeAssist => 0x1,
            Mode::FullOffload => 0x2,
        }
    }
}

#[derive(ValueEnum, Debug, Clone, FromPrimitive, ToPrimitive, PartialEq, Copy)]
#[clap(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClockId {
    ClockTai = CLOCK_TAI as isize,
    ClockRealtime = CLOCK_REALTIME as isize,
    ClockBoottime = CLOCK_BOOTTIME as isize,
    ClockMonotonic = CLOCK_MONOTONIC as isize,
}

impl fmt::Display for ClockId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ClockId::ClockTai => write!(f, "CLOCK_TAI"),
            ClockId::ClockRealtime => write!(f, "CLOCK_REALTIME"),
            ClockId::ClockBoottime => write!(f, "CLOCK_BOOTTIME"),
            ClockId::ClockMonotonic => write!(f, "CLOCK_MONOTONIC"),
        }
    }
}

/// Setup TAPRIO via netlink
pub struct TaprioSetup {
    pub mode: Mode,
    pub clock_id: Option<ClockId>,
    pub txtime_delay: Option<u32>,
    pub tc_fallback: u8,
    pub queues: Vec<String>,
}

impl TaprioSetup {
    fn queues(&self, num_tc: u8) -> Result<Vec<(u16, u16)>> {
        if self.queues.len() > 0 {
            self.queues
                .iter()
                .map(|pair| {
                    let parts: Vec<&str> = pair.split('@').collect();
                    let count = parts
                        .get(0)
                        .ok_or(anyhow!("count missing in queue definition"))?
                        .parse::<u16>()?;
                    let offset = parts
                        .get(1)
                        .ok_or(anyhow!("offset missing in queue definition"))?
                        .parse::<u16>()?;
                    Ok((count, offset))
                })
                .collect()
        } else {
            Ok((0..num_tc).map(|i| (1, i.into())).collect())
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
}

fn setsockopt<T>(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    payload: T,
) -> Result<()> {
    let payload = &payload as *const T as *const libc::c_void;
    let payload_len = mem::size_of::<T>() as libc::socklen_t;

    let res =
        unsafe { libc::setsockopt(fd, level, option, payload, payload_len) };
    if res < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

impl TaprioSetup {
    pub async fn setup(&self, interface_name: &str, schedule: &Schedule) -> Result<()> {
        let (mut connection, handle, _) = rtnetlink::new_connection()?;

        // TODO This should be integrated into netlink-sys
        let fd = connection.socket_mut().as_raw_fd();
        setsockopt(fd, libc::SOL_NETLINK, libc::NETLINK_EXT_ACK, 1)?;

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
                    .ok_or(anyhow!("Cannot convert clock ID"))?,
            );
        }

        if let Some(txtime_delay) = self.txtime_delay {
            req = req.txtime_delay(txtime_delay);
        }

        let result = req.execute().await;

        // TODO Replace this hack with proper support of extended ACKs by netlink library
        if let Err(NetlinkError(err)) = result {
            let msg = std::str::from_utf8(&err.header[20..])?.trim_end_matches('\0');

            let kind = if err.code.is_none() {
                println!("Warning: {msg}");
            } else {
                return Err(anyhow!("{msg}"));
            };
        }

        Ok(())
    }

    pub fn assemble_tc_command(
        &self,
        interface_name: &str,
        schedule: &Schedule,
    ) -> Result<Command> {
        let mut command = Command::new("tc");

        command
            .args(&[
                "qdisc",
                "replace",
                "dev",
                interface_name,
                "parent",
                "root",
                "taprio",
            ])
            .args(&["num_tc", &schedule.number_of_traffic_classes.to_string()])
            .arg("map");

        for prio in &self.priority_map(schedule) {
            command.arg(&prio.to_string());
        }

        command.arg("queues");

        for (count, offset) in &self.queues(schedule.number_of_traffic_classes)? {
            command.arg(format!("{count}@{offset}"));
        }

        command.args(&["base-time", &schedule.basetime_ns.to_string()]);

        for entry in &schedule.control_list {
            command.args(&[
                "sched-entry",
                &Self::operation_char(entry.operation)?.to_string(),
                &entry.gate_states_value.to_string(),
                &entry.time_interval_value_ns.to_string(),
            ]);
        }

        command.args(&["flags", &self.mode.flags().to_string()]);

        if let Some(clock_id) = self.clock_id {
            command.args(&["clockid", &clock_id.to_string()]);
        }

        if let Some(txtime_delay) = self.txtime_delay {
            command.args(&["txtime-delay", &txtime_delay.to_string()]);
        }

        Ok(command)
    }
}
