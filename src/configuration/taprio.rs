// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::configuration::{OptionsBuilder, OptionsGetters, ReplaceNoneOptions};
use anyhow::{anyhow, Result};
use clap::ValueEnum;
use nix::libc::{CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_TAI};
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The TAPRIO offload mode to apply
#[derive(ValueEnum, Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize)]
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
#[derive(
    ValueEnum, Debug, Clone, FromPrimitive, ToPrimitive, PartialEq, Eq, Copy, Serialize, Deserialize,
)]
#[clap(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(clippy::as_conversions)] // as is safe here and there is no reasonable alternative
pub enum Clock {
    /// Clock corresponding to the International Atomic Time (TAI) if available. Not corrected by leap seconds.
    Tai = CLOCK_TAI as isize,

    /// The best effort estimate of UTC that is always available.
    Realtime = CLOCK_REALTIME as isize,

    /// Clock that cannot be set and represents monotonic time since some unspecified starting point.
    Monotonic = CLOCK_MONOTONIC as isize,

    /// Identical to `CLOCK_MONOTONIC`, except it also includes any time that the system is suspended.
    Boottime = CLOCK_BOOTTIME as isize,
}

impl fmt::Display for Clock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tai => write!(f, "CLOCK_TAI"),
            Self::Realtime => write!(f, "CLOCK_REALTIME"),
            Self::Boottime => write!(f, "CLOCK_BOOTTIME"),
            Self::Monotonic => write!(f, "CLOCK_MONOTONIC"),
        }
    }
}

/// Configuration of Linux TAPRIO Qdisc
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
pub struct TaprioConfig {
    /// The offload mode
    pub mode: Option<Mode>,

    /// The clock to use
    pub clock: Option<Clock>,

    /// The maximum time a packet might take to reach the network card from the taprio qdisc.
    /// Only used for `TxTimeAssist` mode.
    pub txtime_delay: Option<u32>,

    /// Count and offset of queue range for each traffic class
    /// If empty, perform a one-to-one mapping of traffic classes and queues (`1@0 1@1 ... 1@<num_tc-1>`).
    pub queues: Option<Vec<QueueMapping>>,
}

/// Defines the queue(s) to be used for a certain traffic class
#[derive(Default, Debug, PartialEq, Eq, Clone, Serialize, Deserialize, ReplaceNoneOptions)]
#[serde(deny_unknown_fields)]
pub struct QueueMapping {
    /// Number of queues for this traffic class
    pub count: u16,

    /// First queue for this traffic class
    pub offset: u16,
}

impl TaprioConfig {
    /// Fill unset fields with defaults for the given number of traffic classes.
    ///
    /// Sets `FullOffload` if `mode` is not provided.
    ///
    /// If `queues` field is not provided, fall back to a one-to-one mapping (`1@0 1@1 ... 1@<num_tc-1>`).
    ///
    /// # Errors
    ///
    /// Returns error if queues field is not None, but no reasonable definition is found
    /// (e.g. `count` or `offset` entries missing or length does not match `num_tc`).
    pub fn fill_defaults(&mut self, num_tc: u8) -> Result<()> {
        if self.mode.is_none() {
            self.mode = Some(Mode::FullOffload);
        }

        if let Some(queues) = &self.queues {
            if queues.len() != num_tc.into() {
                return Err(anyhow!("number of entires in queues needs to match number of traffic classes (or remove completely to fall back to default)"));
            }
        } else {
            self.queues = Some(
                (0..num_tc)
                    .map(|i| QueueMapping {
                        count: 1,
                        offset: i.into(),
                    })
                    .collect(),
            );
        }

        Ok(())
    }

    /// Get mapping of traffic classes to queues as vector of pairs (count, offset)
    ///
    /// # Errors
    ///
    /// Returns error if `queues` field is not set.
    pub fn queue_mapping_as_pairs(&self) -> Result<Vec<(u16, u16)>> {
        Ok(self
            .queues()?
            .iter()
            .map(|queue_mapping| (queue_mapping.count, queue_mapping.offset))
            .collect())
    }
}
