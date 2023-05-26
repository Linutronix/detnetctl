// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later
//
/// PTP Manager
/// In large parts a literal C to Rust translation of
///     <https://github.com/Avnu/tsn-doc/blob/master/misc/check_clocks.c>
///     Copyright (c) 2019, Intel Corporation
///     BSD-3-Clause
/// also including parts of
///     The Linux PTP Project
///     Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
///     GPL-2.0+
use anyhow::{anyhow, Context, Error, Result};
use async_trait::async_trait;
use chrono::{Duration, NaiveDateTime};
use ethtool::EthtoolAttr::TsInfo;
use ethtool::EthtoolTsInfoAttr::PhcIndex;
use flagset::{flags, FlagSet};
use futures::TryStreamExt;
use libc::clockid_t;
use nix::libc;
use nix::poll;
use nix::sys::time::TimeSpec;
use nix::time::{clock_gettime, ClockId};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use std::cmp::max;
use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

use crate::ptp::{
    ClockAccuracy, ClockClass, PortStates, Ptp, PtpConfig, PtpIssue, PtpIssues, PtpStatus,
    PtpTimes, TimeSource,
};

const DEFAULT_UTC_OFFSET: i16 = 37; // only used if no configuration got applied

/// Gateway to Linux PTP
#[derive(Debug)]
pub struct PtpManager {
    applied_config: Option<PtpConfig>,
}

flags! {
    enum TimeFlags: u8 {
        Leap61,
        Leap59,
        UtcOffValid,
        PtpTimescale,
        TimeTraceable,
        FreqTraceable,
        SyncUncertain,
    }
}

/* fd to clockid helpers. Copied from posix-timers.h. */
const CLOCKFD: clockid_t = 3;

/* Borrowed from linuxptp/pmc_common.c */
const MANAGEMENT: u8 = 0xD;
const PTP_VERSION: u8 = 0x2;
const CTL_MANAGEMENT: u8 = 0x4;

const TLV_MANAGEMENT: u16 = 0x0001;
const TLV_MANAGEMENT_ERROR_STATUS: u16 = 0x0002;
const PTP_SOCK: &str = "/var/run/ptp4l";

trait MessageId {
    const MESSAGE_ID: u16;
}
impl MessageId for GrandmasterSettingsNp {
    const MESSAGE_ID: u16 = 0xC001;
}
impl MessageId for TimeStatusNp {
    const MESSAGE_ID: u16 = 0xC000;
}
impl MessageId for PortDataSet {
    const MESSAGE_ID: u16 = 0x2004;
}

#[derive(Debug, FromPrimitive, PartialEq)]
enum ManagementError {
    ResponseTooBig,
    NoSuchId,
    WrongLength,
    WrongValue,
    NotSetable,
    NotSupported,
    GeneralError = 0xFFFE,
}

#[derive(Default, Copy, Clone, Serialize, Deserialize, Debug)]
#[repr(C, packed)]
struct PortId {
    clock_id: [u8; 8],
    port_num: u16,
}

#[derive(Default, Copy, Clone, Serialize, Deserialize, Debug)]
#[repr(C, packed)]
struct PtpHdr {
    tsmt: u8,
    ver: u8,
    msg_len: u16,
    domain_num: u8,
    reserved1: u8,
    flags: u16,
    correction: i64,
    reserved2: u32,
    src_port_id: PortId,
    seq_id: u16,
    control: u8,
    log_interval: i8,
}

#[derive(Default, Copy, Clone, Serialize, Deserialize, Debug)]
#[repr(C, packed)]
struct MgmtMsg {
    hdr: PtpHdr,
    dest_port_id: PortId,
    start_hops: u8,
    boundary_hops: u8,
    flags: u8,
    reserved: u8,
}

#[derive(Default, Copy, Clone, Serialize, Deserialize, Debug)]
#[repr(C, packed)]
struct ManagementTlv {
    mgmt: MgmtMsg,
    msg_type: u16,
    len: u16,
    req_id: u16,
}

#[derive(Default, Copy, Clone, Serialize, Deserialize, Debug)]
#[repr(C, packed)]
struct ManagementErrorStatus {
    mgmt: MgmtMsg,
    msg_type: u16,
    len: u16,
    error: u16,
    id: u16,
    reserved: [u8; 4],
}

#[derive(Default, Copy, Clone, Serialize, Deserialize)]
#[repr(C, packed)]
struct PortDs {
    pid: PortId,
    state: u8,
}

#[derive(Default, Copy, Clone, Serialize, Deserialize)]
#[repr(C, packed)]
struct PortDataSet {
    mgt: ManagementTlv,
    pds: PortDs,
}

#[derive(Default, Copy, Clone, Serialize, Deserialize)]
#[repr(C, packed)]
struct TimeStatusNp {
    mgt: ManagementTlv,
    master_offset: i64,
}

#[derive(Default, Copy, Clone, Serialize, Deserialize, Debug)]
#[repr(C, packed)]
struct GrandmasterSettingsNp {
    mgt: ManagementTlv,
    clock_quality: ClockQuality,
    utc_offset: i16,
    time_flags: u8,
    time_source: u8,
}

#[derive(Default, Copy, Clone, Serialize, Deserialize, Debug)]
#[repr(C, packed)]
struct ClockQuality {
    clock_class: u8,
    clock_accuracy: u8,
    offset_scaled_log_variance: u16,
}

#[allow(dead_code)]
#[derive(ToPrimitive)]
enum Action {
    Get,
    Set,
    Response,
    Command,
    Acknowledge,
}

impl fmt::Display for GrandmasterSettingsNp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "GRANDMASTER_SETTINGS_NP:")?;
        writeln!(
            f,
            "  clockClass              {:?} ({})",
            ClockClass::from_u8(self.clock_quality.clock_class).ok_or(fmt::Error)?,
            self.clock_quality.clock_class
        )?;
        writeln!(
            f,
            "  clockAccuracy           {:?} ({:#x})",
            ClockAccuracy::from_u8(self.clock_quality.clock_accuracy).ok_or(fmt::Error)?,
            self.clock_quality.clock_accuracy
        )?;
        let offset_scaled_log_variance =
            u16::from_be(self.clock_quality.offset_scaled_log_variance);
        writeln!(
            f,
            "  offsetScaledLogVariance {offset_scaled_log_variance:#x}",
        )?;
        writeln!(
            f,
            "  currentUtcOffset        {}",
            i16::from_be(self.utc_offset)
        )?;

        let time_flags = FlagSet::<TimeFlags>::new_truncated(self.time_flags);
        writeln!(
            f,
            "  leap61                  {}",
            time_flags.contains(TimeFlags::Leap61)
        )?;
        writeln!(
            f,
            "  leap59                  {}",
            time_flags.contains(TimeFlags::Leap59)
        )?;
        writeln!(
            f,
            "  currentUtcOffsetValid   {}",
            time_flags.contains(TimeFlags::UtcOffValid)
        )?;
        writeln!(
            f,
            "  ptpTimescale            {}",
            time_flags.contains(TimeFlags::PtpTimescale)
        )?;
        writeln!(
            f,
            "  timeTraceable           {}",
            time_flags.contains(TimeFlags::TimeTraceable)
        )?;
        writeln!(
            f,
            "  frequencyTraceable      {}",
            time_flags.contains(TimeFlags::FreqTraceable)
        )?;
        writeln!(
            f,
            "  syncUncertain           {}",
            time_flags.contains(TimeFlags::SyncUncertain)
        )?;
        writeln!(
            f,
            "  timeSource              {:?} ({:#x})",
            TimeSource::from_u8(self.time_source).ok_or(fmt::Error)?,
            self.time_source
        )?;

        Ok(())
    }
}

#[async_trait]
impl Ptp for PtpManager {
    async fn apply_config(&self, config: &PtpConfig) -> Result<()> {
        println!("Applying PTP configuration {config:#?}");

        let mut time_flags = FlagSet::<TimeFlags>::new_truncated(0);
        if config.leap61 {
            time_flags |= TimeFlags::Leap61;
        }
        if config.leap59 {
            time_flags |= TimeFlags::Leap59;
        }
        if config.current_utc_offset_valid {
            time_flags |= TimeFlags::UtcOffValid;
        }
        if config.ptp_timescale {
            time_flags |= TimeFlags::PtpTimescale;
        }
        if config.time_traceable {
            time_flags |= TimeFlags::TimeTraceable;
        }
        if config.frequency_traceable {
            time_flags |= TimeFlags::FreqTraceable;
        }

        let data_length = u16::try_from(mem::size_of::<GrandmasterSettingsNp>())?
            .checked_sub(u16::try_from(mem::size_of::<ManagementTlv>())?)
            .ok_or_else(|| anyhow!("Negative data length"))?;

        let msg = GrandmasterSettingsNp {
            mgt: ManagementTlv::new(
                GrandmasterSettingsNp::MESSAGE_ID,
                config.gptp_profile,
                &Action::Set,
                data_length,
            )?,
            clock_quality: ClockQuality {
                clock_class: config
                    .clock_class
                    .to_u8()
                    .ok_or_else(|| anyhow!("Cannot convert clock class"))?,
                clock_accuracy: config
                    .clock_accuracy
                    .to_u8()
                    .ok_or_else(|| anyhow!("Cannot convert clock accuracy"))?,
                offset_scaled_log_variance: config.offset_scaled_log_variance.to_be(),
            },
            utc_offset: config.current_utc_offset.to_be(),
            time_flags: time_flags.bits(),
            time_source: config
                .time_source
                .to_u8()
                .ok_or_else(|| anyhow!("Cannot covert time source"))?,
        };

        println!("Sending {msg}");

        let dest_addr = Path::new(PTP_SOCK).to_owned();
        let mut uds_fd = UnixDatagram::bind("")?;
        let response: GrandmasterSettingsNp = send_wait_recv(&mut uds_fd, &dest_addr, &msg)
            .with_context(|| {
                let has_gptp = if config.gptp_profile { "" } else { "No " };
                format!("Sending grandmaster settings failed. ({}gPTP profile configured. Does that match ptp4l?)", has_gptp)
            })?;

        println!("Received response {response}");

        Ok(())
    }

    async fn get_status(
        &self,
        ifname: &str,
        max_clock_delta: Duration,
        max_master_offset: Duration,
    ) -> Result<PtpStatus> {
        let mut utc_offset = DEFAULT_UTC_OFFSET;
        if let Some(config) = &self.applied_config {
            utc_offset = config.current_utc_offset;
        }

        let times = get_ptp_times(ifname)
            .await
            .context("Requesting timestamps")?;

        let mut issues = check_local_clock(&times, utc_offset, max_clock_delta)?;

        let (master_offset, port_state, offset_issues) =
            check_ptp_offset(max_master_offset).context("Checking PTP offset")?;
        issues |= offset_issues;

        let (kernel_tai_offset, tai_issues) =
            check_kernel_tai_offset(utc_offset).context("Checking Kernel TAI offset")?;
        issues |= tai_issues;

        Ok(PtpStatus {
            issues,
            times,
            kernel_tai_offset: Duration::seconds(kernel_tai_offset.into()),
            port_state,
            master_offset,
        })
    }
}

impl PtpManager {
    /// Create new PTP manager
    #[must_use]
    pub const fn new() -> Self {
        Self {
            applied_config: None,
        }
    }
}

const fn make_process_cpuclock(pid: i32, clock: clockid_t) -> clockid_t {
    ((!pid) << 3) | clock
}

const fn fd_to_clockid(fd: i32) -> ClockId {
    ClockId::from_raw(make_process_cpuclock(fd, CLOCKFD))
}

async fn get_phc_index(interface: &str) -> Result<u32> {
    let (connection, mut handle, _) = ethtool::new_connection()?;
    tokio::spawn(connection);

    let mut tsinfo_handle = handle.tsinfo().get(Some(interface)).execute().await;

    while let Some(msg) = tsinfo_handle.try_next().await? {
        let idx = msg.payload.nlas.iter().find_map(|d| match d {
            TsInfo(PhcIndex(idx)) => Some(idx),
            _ => None,
        });

        if let Some(idx) = idx {
            return Ok(*idx);
        }
    }

    Err(anyhow!("No ethtool ts info message received"))
}

async fn open_phc_fd(ifname: &str) -> Result<File> {
    let ptp_path = format!("/dev/ptp{}", get_phc_index(ifname).await?);
    Ok(OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .open(ptp_path)?)
}

struct PtpNaiveDateTime(NaiveDateTime);
impl TryFrom<TimeSpec> for PtpNaiveDateTime {
    type Error = Error;

    fn try_from(item: TimeSpec) -> Result<Self, Self::Error> {
        Ok(Self(
            NaiveDateTime::from_timestamp_opt(item.tv_sec(), u32::try_from(item.tv_nsec())?)
                .ok_or_else(|| anyhow!("Time out of range"))?,
        ))
    }
}

struct PtpDuration(Duration);
impl TryFrom<TimeSpec> for PtpDuration {
    type Error = Error;
    fn try_from(item: TimeSpec) -> Result<Self> {
        Ok(Self(
            Duration::seconds(item.tv_sec())
                .checked_add(&Duration::nanoseconds(item.tv_nsec()))
                .ok_or_else(|| anyhow!("Cannot convert timespec to duration"))?,
        ))
    }
}

async fn get_ptp_times(ifname: &str) -> Result<PtpTimes> {
    let fd_ptp = open_phc_fd(ifname).await?;

    // Fetch timestamps for each clock
    let rt = clock_gettime(ClockId::CLOCK_REALTIME)?;
    let tai = clock_gettime(ClockId::CLOCK_TAI)?;
    let ptp = clock_gettime(fd_to_clockid(fd_ptp.as_raw_fd()))?;

    // Compute clocks read latency
    let rt1 = clock_gettime(ClockId::CLOCK_REALTIME)?;
    let rt2 = clock_gettime(ClockId::CLOCK_REALTIME)?;
    let lat_rt = rt2 - rt1;

    let tai1 = clock_gettime(ClockId::CLOCK_TAI)?;
    let tai2 = clock_gettime(ClockId::CLOCK_TAI)?;
    let lat_tai = tai2 - tai1;

    let ptp1 = clock_gettime(fd_to_clockid(fd_ptp.as_raw_fd()))?;
    let ptp2 = clock_gettime(fd_to_clockid(fd_ptp.as_raw_fd()))?;
    let lat_ptp = ptp2 - ptp1;

    let phc_rt = ptp - rt;
    let phc_tai = ptp - tai;

    Ok(PtpTimes {
        rt: PtpNaiveDateTime::try_from(rt)?.0,
        tai: PtpNaiveDateTime::try_from(tai)?.0,
        ptp: PtpNaiveDateTime::try_from(ptp)?.0,
        lat_rt: PtpDuration::try_from(lat_rt)?.0,
        lat_tai: PtpDuration::try_from(lat_tai)?.0,
        lat_ptp: PtpDuration::try_from(lat_ptp)?.0,
        phc_rt: PtpDuration::try_from(phc_rt)?.0,
        phc_tai: PtpDuration::try_from(phc_tai)?.0,
    })
}

fn check_local_clock(
    ptp_times: &PtpTimes,
    utc_offset: i16,
    max_clock_delta: Duration,
) -> Result<PtpIssues> {
    let mut issues: PtpIssues = None.into();
    if !is_duration_small_enough(
        ptp_times
            .phc_rt
            .checked_sub(&Duration::seconds(utc_offset.into()))
            .ok_or_else(|| anyhow!("Calculating RT delta failed"))?,
        max_clock_delta,
    )? {
        issues |= PtpIssue::PhcRtDeltaNotOk;
    }

    if !is_duration_small_enough(ptp_times.phc_tai, max_clock_delta)? {
        issues |= PtpIssue::PhcTaiDeltaNotOk;
    }

    Ok(issues)
}

fn check_kernel_tai_offset(utc_offset: i16) -> Result<(i32, PtpIssues)> {
    // SAFETY:
    // tbuf will be filled by adjtimex
    let mut tbuf: libc::timex = unsafe { mem::zeroed() };

    // SAFETY:
    // Only writes to tbuf
    if unsafe { libc::adjtimex(&mut tbuf) } == -1 {
        return Err(anyhow!(
            "adjtimex() failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut issues: PtpIssues = None.into();
    if tbuf.tai != utc_offset.into() {
        issues |= PtpIssue::KernelTaiOffsetNotOk;
    }

    Ok((tbuf.tai, issues))
}

fn send_wait_recv<T: Serialize, R: for<'a> Deserialize<'a> + MessageId>(
    uds_fd: &mut UnixDatagram,
    dest_addr: &Path,
    req: &T,
) -> Result<R> {
    // both the actual response type as well as the error status have to fit into the buffer
    let size = max(mem::size_of::<R>(), mem::size_of::<ManagementErrorStatus>());
    let mut rec_buf = vec![0; size];
    let serialized = bincode::serialize(req)?;

    if uds_fd.send_to(&serialized, dest_addr)? == serialized.len() {
        let pollfd = poll::PollFd::new(
            uds_fd.as_raw_fd(),
            poll::PollFlags::POLLIN | poll::PollFlags::POLLERR,
        );
        let poll_result = poll::poll(&mut [pollfd], 3000)?;

        if poll_result != 1 {
            return Err(anyhow!("poll() returned {}", poll_result));
        }

        uds_fd.recv(&mut rec_buf)?;

        let rec_hdr: ManagementTlv = bincode::deserialize(&rec_buf)?;
        let message_type = u16::from_be(rec_hdr.msg_type);
        match message_type {
            TLV_MANAGEMENT => {
                let message_id = u16::from_be(rec_hdr.req_id);
                if message_id != R::MESSAGE_ID {
                    return Err(anyhow!(
                        "Invalid message received with message ID {}",
                        message_id
                    ));
                }

                Ok(bincode::deserialize(&rec_buf)?)
            }
            TLV_MANAGEMENT_ERROR_STATUS => {
                let error_status: ManagementErrorStatus = bincode::deserialize(&rec_buf)?;
                let error_code = u16::from_be(error_status.error);
                let error: ManagementError =
                    FromPrimitive::from_u16(u16::from_be(error_status.error)).ok_or_else(|| {
                        anyhow!(
                            "Received PTP error message with unknown error code {}",
                            error_code
                        )
                    })?;
                Err(anyhow!(
                    "Received Ptp error message: {:?} ({})",
                    error,
                    error_code
                ))
            }
            _ => Err(anyhow!(
                "Invalid message received with message type {}",
                message_type
            )),
        }
    } else {
        Err(anyhow!("Failed to send PTP management packet"))
    }
}

impl ManagementTlv {
    fn new(req_id: u16, gptp_profile: bool, action: &Action, data_length: u16) -> Result<Self> {
        let mut ptp_req = Self::default();

        if gptp_profile {
            ptp_req.mgmt.hdr.tsmt = (0x1 << 4) | MANAGEMENT;
        } else {
            ptp_req.mgmt.hdr.tsmt = MANAGEMENT;
        }

        ptp_req.mgmt.hdr.ver = PTP_VERSION;

        ptp_req.mgmt.hdr.msg_len = (u16::try_from(mem::size_of::<Self>())? + data_length).to_be();

        /*
         * FIXME: Linuxptp's pmc uses 1 for port id. At this point
         * I am unable to find a reason in the 1588 spec. Please
         * explain if you find the reason or otherwise fix this.
         */
        ptp_req.mgmt.hdr.src_port_id.port_num = 0x1_u16.to_be();
        ptp_req.mgmt.hdr.control = CTL_MANAGEMENT;
        ptp_req.mgmt.hdr.log_interval = 0x7F;

        // All 1's for destination port
        ptp_req
            .mgmt
            .dest_port_id
            .clock_id
            .iter_mut()
            .for_each(|x| *x = 0xFF);
        ptp_req.mgmt.dest_port_id.port_num = 0xFFFF;

        ptp_req.msg_type = TLV_MANAGEMENT.to_be();

        // 1588 spec says "2 + datalen"
        ptp_req.len = (2_u16 + data_length).to_be();
        ptp_req.req_id = req_id.to_be();

        // Set flag according to action
        ptp_req.mgmt.flags = action
            .to_u8()
            .ok_or_else(|| anyhow!("Action does not convert"))?;

        Ok(ptp_req)
    }
}

fn check_ptp_offset(max_master_offset: Duration) -> Result<(Duration, PortStates, PtpIssues)> {
    let dest_addr = Path::new(PTP_SOCK).to_owned();
    let mut gptp_profile = false;
    let mut offset = Duration::zero();
    let mut uds_fd = UnixDatagram::bind("").context("Binding to Unix datagram socket")?;

    let mut port_req = ManagementTlv::new(PortDataSet::MESSAGE_ID, gptp_profile, &Action::Get, 0)?;
    let mut resp_port_result: Result<PortDataSet> =
        send_wait_recv(&mut uds_fd, &dest_addr, &port_req);
    if resp_port_result.is_err() {
        /*
         * Send the same request again with the transportSpecific field
         * set to 0x1. This is needed when running the 802.1AS (or
         * gPTP) profile. (For details see,  IEEE 802.1AS-2011
         * 10.5.2.2.1)
         */
        gptp_profile = true;
        port_req = ManagementTlv::new(PortDataSet::MESSAGE_ID, gptp_profile, &Action::Get, 0)?;
        resp_port_result = send_wait_recv(&mut uds_fd, &dest_addr, &port_req);
    }

    let port_state = FromPrimitive::from_u8(
        resp_port_result
            .context("Requesting port state from ptp4l")?
            .pds
            .state,
    )
    .ok_or_else(|| anyhow!("Can't parse port state"))?;

    let mut issues: PtpIssues = match port_state {
        PortStates::Master | PortStates::Slave | PortStates::GrandMaster => None.into(),
        _ => PtpIssue::PortStateNotOk.into(),
    };

    if port_state == PortStates::Slave {
        let time_req = ManagementTlv::new(TimeStatusNp::MESSAGE_ID, gptp_profile, &Action::Get, 0)?;
        let offset_response: TimeStatusNp = send_wait_recv(&mut uds_fd, &dest_addr, &time_req)?;
        offset = Duration::nanoseconds(i64::from_be(offset_response.master_offset));
    }

    if !is_duration_small_enough(offset, max_master_offset)? {
        issues |= PtpIssue::MasterOffsetNotOk;
    }

    Ok((offset, port_state, issues))
}

fn is_duration_small_enough(mut value: Duration, max: Duration) -> Result<bool> {
    if max < Duration::zero() {
        return Err(anyhow!("Maximum duration is negative"));
    }

    // calculate absolute duration
    if value < Duration::zero() {
        value = Duration::zero()
            .checked_sub(&value)
            .ok_or_else(|| anyhow!("invalid duration"))?;
    }

    Ok(value <= max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_happy_duration_check() -> Result<()> {
        assert!(!is_duration_small_enough(
            Duration::nanoseconds(-10),
            Duration::nanoseconds(5)
        )?);
        assert!(is_duration_small_enough(
            Duration::nanoseconds(-10),
            Duration::nanoseconds(20)
        )?);
        assert!(!is_duration_small_enough(
            Duration::nanoseconds(10),
            Duration::nanoseconds(5)
        )?);
        assert!(is_duration_small_enough(
            Duration::nanoseconds(10),
            Duration::nanoseconds(20)
        )?);

        Ok(())
    }
}
