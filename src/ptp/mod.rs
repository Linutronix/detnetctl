// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Manage PTP
use anyhow::Result;
use async_trait::async_trait;
use chrono::{Duration, NaiveDateTime};
use flagset::{flags, FlagSet};

#[cfg(test)]
use mockall::automock;

#[cfg(feature = "ptp")]
mod ptp_manager;
#[cfg(feature = "ptp")]
pub use ptp_manager::PtpManager;

mod model;
pub use model::*;

/// Times, latencies and differences of various clocks
#[derive(Debug)]
#[allow(dead_code)] // only Debug output is used for reading at the moment
pub struct PtpTimes {
    /// Current CLOCK_REALTIME
    pub rt: NaiveDateTime,

    /// Current CLOCK_TAI
    pub tai: NaiveDateTime,

    /// Current PTP clock
    pub ptp: NaiveDateTime,

    /// Read latency of CLOCK_READTIME
    pub lat_rt: Duration,

    /// Read latency of CLOCK_TAI
    pub lat_tai: Duration,

    /// Read latency of PTP clock
    pub lat_ptp: Duration,

    /// PTP Clock - CLOCK_REALTIME
    pub phc_rt: Duration,

    /// PTP Clock - CLOCK_TAI
    pub phc_tai: Duration,
}

flags! {
    /// Flags indicating various PTP related issues
    #[allow(clippy::enum_variant_names)]
    pub enum PtpIssue: u8 {
        /// phc-rt delta is not near to the UTC offset
        PhcRtDeltaNotOk,

        /// phc-tai is too large
        PhcTaiDeltaNotOk,

        /// UTC-TAI offset configured in the kernel does not match
        KernelTaiOffsetNotOk,

        /// Port state is not master, slave or grand master
        PortStateNotOk,

        /// Master offset too large
        MasterOffsetNotOk,
    }
}

type PtpIssues = FlagSet<PtpIssue>;

/// Status of PTP synchronization
#[derive(Debug)]
pub struct PtpStatus {
    /// Flags indicating various PTP related issues
    pub issues: PtpIssues,

    /// Times, latencies and differences of various clocks
    pub times: PtpTimes,

    /// UTC-TAI offset configured in the kernel
    pub kernel_tai_offset: Duration,

    /// State of the PTP port
    pub port_state: PortStates,

    /// Master offset
    pub master_offset: Duration,
}

/// Defines how to configure and request the status of PTP
#[async_trait]
#[cfg_attr(test, automock)]
pub trait Ptp {
    /// Apply the given configuration
    async fn apply_config(&self, config: &PtpConfig) -> Result<()>;

    /// Get the current PTP status
    async fn get_status(
        &self,
        ifname: &str,
        max_clock_delta: Duration,
        max_master_offset: Duration,
    ) -> Result<PtpStatus>;
}
