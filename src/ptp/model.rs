// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later
//
#![allow(clippy::as_conversions)] // for Serialize_repr

use crate::configuration::ReplaceNoneOptions;
/// PTP Data Model
/// Elements and descriptions taken from IEEE Std 1588 and its corresponding YANG model
use anyhow::{anyhow, Error, Result};
use num_derive::{FromPrimitive, ToPrimitive};
use options_struct_derive::{OptionsBuilder, OptionsGetters, ReplaceNoneOptions};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::str::FromStr;

/// State of the PTP port
#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq, Eq)]
pub enum PortStates {
    /// The PTP Port is initializing its data sets, hardware, and
    /// communication facilities. The PTP Port shall not place any
    /// PTP messages on its communication path.
    Initializing = 1,

    /// The fault state of the protocol. Except for PTP management
    /// messages that are a required response to a PTP message
    /// received from the applicable management mechanism,
    /// a PTP Port in this state shall not transmit any PTP related
    /// messages. In a Boundary Clock, no activity on a faulty
    /// PTP Port shall affect the other PTP Ports of the
    /// PTP Instance. If fault activity on a PTP Port in this state
    /// cannot be confined to the faulty PTP Port, then all
    Faulty = 2,

    /// The PTP Port is disabled. Except for PTP management
    /// messages that are a required response to a PTP message
    /// received from the applicable management mechanism,
    /// a PTP Port in this state shall not transmit any PTP related
    /// messages. In a Boundary Clock, no activity at the PTP Port
    /// shall be allowed to affect the activity at any other
    /// PTP Port of the Boundary Clock. A PTP Port in this state
    /// shall discard all received PTP messages except for PTP
    /// management messages.
    Disabled = 3,

    /// The PTP Port is waiting for the announce-receipt-timeout
    /// to expire or to receive an Announce message from a
    /// Master PTP Instance. The purpose of this state is to allow
    /// orderly addition of PTP Instances to a domain
    /// (i.e. to know if this PTP Port is truly a port of the
    /// Grandmaster PTP Instance prior to taking that role).
    Listening = 4,

    /// This port state provides an additional mechanism to
    /// support more orderly reconfiguration of PTP Networks when
    /// PTP Instances are added or deleted, PTP Instance
    /// characteristics change, or connection topology changes.
    /// In this state, a PTP Port behaves as it would if it were in
    /// the master state except that it does not place certain
    /// classes of PTP messages on the PTP Communication Path
    /// associated with the PTP Port.
    PreMaster = 5,

    /// The PTP Port is the source of time on the
    /// PTP Communication Path.
    Master = 6,

    /// The PTP Port is not the source of time on the
    /// PTP Communication Path nor does it synchronize to a
    /// Master Clock (receive time). The PTP Port can potentially
    /// change to slave when PTP Instances are added or deleted,
    /// PTP Instance characteristics change, or connection
    /// topology changes.
    Passive = 7,

    /// The PTP Port is anticipating a change to the slave state,
    /// but it has not yet satisfied all requirements
    /// (implementation or PTP Profile) necessary to ensure
    /// complete synchronization. For example, an implementation
    /// might require a minimum number of PTP Sync messages
    /// in order to completely synchronize its servo algorithm.
    Uncalibrated = 8,

    /// The PTP Port synchronizes to the PTP Port on the
    /// PTP Communication Path that is in the master state
    /// (i.e. receives time).
    Slave = 9,

    /// The PTP Port is the top-level source of time on the
    /// PTP Communication Path.
    GrandMaster = 10,
}

/// Enumeration that denotes the traceability, synchronization
/// state and expected performance of the time or frequency
/// distributed by the Grandmaster PTP Instance.
#[derive(
    Debug, PartialEq, Eq, Copy, Clone, Serialize_repr, Deserialize_repr, ToPrimitive, FromPrimitive,
)]
#[repr(u8)]
pub enum ClockClass {
    /// A PTP Instance that is synchronized to a primary
    /// reference time source. The timescale distributed shall be PTP.
    /// Numeric value is 6 decimal.
    PrimarySync = 6,

    /// A PTP Instance that has previously been designated
    /// as clockClass 6, but that has lost the ability to
    /// synchronize to a primary reference time source and is in
    /// holdover mode and within holdover specifications. Or a PTP
    /// Instance designated with clockClass 7 based on the Holdover
    /// Upgrade option. The timescale distributed shall be PTP.
    /// Numeric value is 7 decimal.
    PrimarySyncLost = 7,

    /// A PTP Instance that is synchronized to an
    /// application-specific source of time. The timescale
    /// distributed shall be ARB.
    /// Numeric value is 13 decimal.
    ApplicationSpecificSync = 13,

    /// A PTP Instance that has previously been designated as
    /// clockClass 13, but that has lost the ability to synchronize
    /// to an application-specific source of time and is in
    /// holdover mode and within holdover specifications. Or a PTP
    /// Instance designated with clockClass 14 based on the Holdover
    /// Upgrade option. The timescale distributed shall be ARB.
    /// Numeric value is 14 decimal.
    ApplicationSpecificSyncLost = 14,

    /// Degradation alternative A for a PTP Instance of
    /// clockClass 7 that is not within holdover specification
    /// or that is based on the specifications of the Holdover
    /// Upgrade option.
    /// Numeric value is 52 decimal.
    PrimarySyncAlternativeA = 52,

    /// Degradation alternative A for a PTP Instance of
    /// clockClass 14 that is not within holdover specification or
    /// that is based on the specifications of the Holdover Upgrade
    /// option.
    /// Numeric value is 58 decimal.
    ApplicationSpecificAlternativeA = 58,

    /// Degradation alternative B for a PTP Instance of
    /// clockClass 7 that is not within holdover specification
    /// or that is based on the specifications of the Holdover
    /// Upgrade option.
    /// Numeric value is 187 decimal.
    PrimarySyncAlternativeB = 187,

    /// Degradation alternative B for a PTP Instance of
    /// clockClass 14 that is not within holdover specification or
    /// that is based on the specifications of the Holdover Upgrade
    /// option.
    /// Numeric value is 193 decimal.
    ApplicationSpecificAlternativeB = 193,

    /// Default clockClass, used if none of the other
    /// clockClass definitions apply.
    /// Numeric value is 248 decimal.
    Default = 248,

    /// A PTP Instance that is slave-only.
    /// Numeric value is 255 decimal.
    SlaveOnly = 255,
}

impl FromStr for ClockClass {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        match strip_prefix(input) {
            "cc-primary-sync" => Ok(Self::PrimarySync),
            "cc-primary-sync-lost" => Ok(Self::PrimarySyncLost),
            "cc-application-specific-sync" => Ok(Self::ApplicationSpecificSync),
            "cc-application-specific-sync-lost" => Ok(Self::ApplicationSpecificSyncLost),
            "cc-primary-sync-alternative-a" => Ok(Self::PrimarySyncAlternativeA),
            "cc-application-specific-alternative-a" => Ok(Self::ApplicationSpecificAlternativeA),
            "cc-primary-sync-alternative-b" => Ok(Self::PrimarySyncAlternativeB),
            "cc-application-specific-alternative-b" => Ok(Self::ApplicationSpecificAlternativeB),
            "cc-default" => Ok(Self::Default),
            "cc-slave-only" => Ok(Self::SlaveOnly),
            _ => Err(anyhow!("Can not parse {} as clock class", input)),
        }
    }
}

/// Enumeration that indicates the expected accuracy of a
/// PTP Instance when it is the Grandmaster PTP Instance,
/// or in the event it becomes the Grandmaster PTP Instance.
#[derive(
    Debug, PartialEq, Eq, Copy, Clone, Serialize_repr, Deserialize_repr, ToPrimitive, FromPrimitive,
)]
#[repr(u8)]
pub enum ClockAccuracy {
    /// The time is accurate to within 1 ps (1000 fs).
    /// Numeric value is 17 hex.
    TimeAccurateTo1000Fs = 0x17,
    /// The time is accurate to within 2.5 ps (2500 fs).
    /// Numeric value is 18 hex.
    TimeAccurateTo2500Fs = 0x18,
    /// The time is accurate to within 10 ps.
    /// Numeric value is 19 hex.
    TimeAccurateTo10Ps = 0x19,
    /// The time is accurate to within 25 ps.
    /// Numeric value is 1A hex.
    TimeAccurateTo25Ps = 0x1A,
    /// The time is accurate to within 100 ps.
    /// Numeric value is 1B hex.
    TimeAccurateTo100Ps = 0x1B,
    /// The time is accurate to within 250 ps.
    /// Numeric value is 1C hex.
    TimeAccurateTo250Ps = 0x1C,
    /// The time is accurate to within 1ns (1000 ps).
    /// Numeric value is 1D hex.
    TimeAccurateTo1000Ps = 0x1D,
    /// The time is accurate to within 2.5 ns (2500 ps).
    /// Numeric value is 1E hex.
    TimeAccurateTo2500Ps = 0x1E,
    /// The time is accurate to within 10 ns.
    /// Numeric value is 1F hex.
    TimeAccurateTo10Ns = 0x1F,
    /// The time is accurate to within 25 ns.
    /// Numeric value is 20 hex.
    TimeAccurateTo25Ns = 0x20,
    /// The time is accurate to within 100 ns.
    /// Numeric value is 21 hex.
    TimeAccurateTo100Ns = 0x21,
    /// The time is accurate to within 250 ns.
    /// Numeric value is 22 hex.
    TimeAccurateTo250Ns = 0x22,
    /// The time is accurate to within 1 us (1000 ns).
    /// Numeric value is 23 hex.
    TimeAccurateTo1000Ns = 0x23,
    /// The time is accurate to within 2.5 us (2500 ns).
    /// Numeric value is 24 hex.
    TimeAccurateTo2500Ns = 0x24,
    /// The time is accurate to within 10 us.
    /// Numeric value is 25 hex.
    TimeAccurateTo10Us = 0x25,
    /// The time is accurate to within 25 us.
    /// Numeric value is 26 hex.
    TimeAccurateTo25Us = 0x26,
    /// The time is accurate to within 100 us.
    /// Numeric value is 27 hex.
    TimeAccurateTo100Us = 0x27,
    /// The time is accurate to within 250 us.
    /// Numeric value is 28 hex.
    TimeAccurateTo250Us = 0x28,
    /// The time is accurate to within 1 ms (1000 us).
    /// Numeric value is 29 hex.
    TimeAccurateTo1000Us = 0x29,
    /// The time is accurate to within 2.5 ms (2500 us).
    /// Numeric value is 2A hex.
    TimeAccurateTo2500Us = 0x2A,
    /// The time is accurate to within 10 ms.
    /// Numeric value is 2B hex.
    TimeAccurateTo10Ms = 0x2B,
    /// The time is accurate to within 25 ms.
    /// Numeric value is 2C hex.
    TimeAccurateTo25Ms = 0x2C,
    /// The time is accurate to within 100 ms.
    /// Numeric value is 2D hex.
    TimeAccurateTo100Ms = 0x2D,
    /// The time is accurate to within 250 ms.
    /// Numeric value is 2E hex.
    TimeAccurateTo250Ms = 0x2E,
    /// The time is accurate to within 1 s.
    /// Numeric value is 2F hex.
    TimeAccurateTo1S = 0x2F,
    /// The time is accurate to within 10 s.
    /// Numeric value is 30 hex.
    TimeAccurateTo10S = 0x30,
    /// The time accuracy exceeds 10 s.
    /// Numeric value is 31 hex.
    TimeAccurateToGreaterThan10S = 0x31,
}

impl FromStr for ClockAccuracy {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        match strip_prefix(input) {
            "ca-time-accurate-to-1000-fs" => Ok(Self::TimeAccurateTo1000Fs),
            "ca-time-accurate-to-2500-fs" => Ok(Self::TimeAccurateTo2500Fs),
            "ca-time-accurate-to-10-ps" => Ok(Self::TimeAccurateTo10Ps),
            "ca-time-accurate-to-25ps" => Ok(Self::TimeAccurateTo25Ps),
            "ca-time-accurate-to-100-ps" => Ok(Self::TimeAccurateTo100Ps),
            "ca-time-accurate-to-250-ps" => Ok(Self::TimeAccurateTo250Ps),
            "ca-time-accurate-to-1000-ps" => Ok(Self::TimeAccurateTo1000Ps),
            "ca-time-accurate-to-2500-ps" => Ok(Self::TimeAccurateTo2500Ps),
            "ca-time-accurate-to-10-ns" => Ok(Self::TimeAccurateTo10Ns),
            "ca-time-accurate-to-25-ns" => Ok(Self::TimeAccurateTo25Ns),
            "ca-time-accurate-to-100-ns" => Ok(Self::TimeAccurateTo100Ns),
            "ca-time-accurate-to-250-ns" => Ok(Self::TimeAccurateTo250Ns),
            "ca-time-accurate-to-1000-ns" => Ok(Self::TimeAccurateTo1000Ns),
            "ca-time-accurate-to-2500-ns" => Ok(Self::TimeAccurateTo2500Ns),
            "ca-time-accurate-to-10-us" => Ok(Self::TimeAccurateTo10Us),
            "ca-time-accurate-to-25-us" => Ok(Self::TimeAccurateTo25Us),
            "ca-time-accurate-to-100-us" => Ok(Self::TimeAccurateTo100Us),
            "ca-time-accurate-to-250-us" => Ok(Self::TimeAccurateTo250Us),
            "ca-time-accurate-to-1000-us" => Ok(Self::TimeAccurateTo1000Us),
            "ca-time-accurate-to-2500-us" => Ok(Self::TimeAccurateTo2500Us),
            "ca-time-accurate-to-10-ms" => Ok(Self::TimeAccurateTo10Ms),
            "ca-time-accurate-to-25-ms" => Ok(Self::TimeAccurateTo25Ms),
            "ca-time-accurate-to-100-ms" => Ok(Self::TimeAccurateTo100Ms),
            "ca-time-accurate-to-250-ms" => Ok(Self::TimeAccurateTo250Ms),
            "ca-time-accurate-to-1-s" => Ok(Self::TimeAccurateTo1S),
            "ca-time-accurate-to-10-s" => Ok(Self::TimeAccurateTo10S),
            "ca-time-accurate-to-gt-10-s" => Ok(Self::TimeAccurateToGreaterThan10S),
            _ => Err(anyhow!("Can not parse {} as clock accuracy", input)),
        }
    }
}

/// Enumeration for the source of time used by the Grandmaster PTP Instance.
#[derive(
    Debug, PartialEq, Eq, Copy, Clone, Serialize_repr, Deserialize_repr, ToPrimitive, FromPrimitive,
)]
#[repr(u8)]
pub enum TimeSource {
    /// Any PTP Instance that is based on an atomic resonance for frequency,
    /// or a PTP Instance directly connected to a device that is based on an atomic resonance for frequency.
    /// Numeric value is 0x10 hex.
    AtomicClock = 0x10,
    /// Any PTP Instance synchronized to a satellite system that distributes time and frequency.
    /// Numeric value is 0x20 hex.
    Gnss = 0x20,
    /// Any PTP Instance synchronized via any of the radio distribution systems that distribute time and frequency.
    /// Numeric value is 0x30 hex.
    TerrestrialRadio = 0x30,
    /// Any PTP Instance synchronized via any of the serial time code distribution systems that distribute time and frequency, for example, IRIG-B.
    /// Numeric value is 0x39 hex.
    SerialTimeCode = 0x39,
    /// Any PTP Instance synchronized to a PTP-based source of time external to the domain.
    /// Numeric value is 0x40 hex.
    Ptp = 0x40,
    /// Any PTP Instance synchronized via NTP or Simple Network Time Protocol (SNTP) servers that distribute time and frequency.
    /// Numeric value is 0x50 hex.
    Ntp = 0x50,
    /// Used for any PTP Instance whose time has been set by means of a human interface based on observation of a source of time to within the claimed clock accuracy.
    /// Numeric value is 0x60 hex.
    HandSet = 0x60,
    /// Other source of time and/or frequency not covered by other values.
    /// Numeric value is 0x90 hex.
    Other = 0x90,
    /// Any PTP Instance whose frequency is not based on atomic resonance, and whose time is based on a free-running oscillator with epoch determined in an arbitrary or unknown manner.
    /// Numeric value is 0xA0 hex.
    InternalOscillator = 0xA0,
}

impl FromStr for TimeSource {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        match strip_prefix(input) {
            "atomic-clock" => Ok(Self::AtomicClock),
            "gnss" => Ok(Self::Gnss),
            "terrestrial-radio" => Ok(Self::TerrestrialRadio),
            "serial-time-code" => Ok(Self::SerialTimeCode),
            "ptp" => Ok(Self::Ptp),
            "ntp" => Ok(Self::Ntp),
            "hand-set" => Ok(Self::HandSet),
            "other" => Ok(Self::Other),
            "internal-oscillator" => Ok(Self::InternalOscillator),
            _ => Err(anyhow!("Can not parse {} as time source", input)),
        }
    }
}

/// Configuration for PTP Grandmaster
#[derive(
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
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct PtpInstanceConfig {
    /// Enumeration that denotes the traceability, synchronization
    /// state and expected performance of the time or frequency
    /// distributed by the Grandmaster PTP Instance.
    clock_class: Option<ClockClass>,

    /// Enumeration that indicates the expected accuracy of a
    /// PTP Instance when it is the Grandmaster PTP Instance,
    /// or in the event it becomes the Grandmaster PTP Instance.
    clock_accuracy: Option<ClockAccuracy>,

    /// The offsetScaledLogVariance indicates the stability of the
    /// clock (Local Clock of the PTP Instance). It provides an
    /// estimate of the variations of the clock from a linear timescale
    /// when it is not synchronized to another clock using the protocol.
    offset_scaled_log_variance: Option<u16>,

    /// Specified as dLS in IERS Bulletin C, this provides
    /// the offset from UTC (TAI - UTC). The offset is in
    /// units of seconds.
    current_utc_offset: Option<i16>,

    /// The value of current-utc-offset-valid shall be true
    /// if the values of current-utc-offset, leap59, and leap61
    /// are known to be correct, otherwise it shall be false.
    current_utc_offset_valid: Option<bool>,

    /// If the timescale is PTP, a true value for leap59
    /// shall indicate that the last minute of the
    /// current UTC day contains 59 seconds.
    /// If the timescale is not PTP, the value shall be
    /// false.
    leap59: Option<bool>,

    /// If the timescale is PTP, a true value for leap61
    /// shall indicate that the last minute of the
    /// current UTC day contains 61 seconds.
    /// If the timescale is not PTP, the value shall be
    /// false.
    leap61: Option<bool>,

    /// The value of time-traceable shall be true if the
    /// timescale is traceable to a primary reference;
    /// otherwise, the value shall be false.
    /// The uncertainty specifications appropriate to the
    /// evaluation of whether traceability to a primary
    /// reference is achieved should be defined in the
    /// applicable PTP Profile. In the absence of such a
    /// definition the value of time-traceable is
    /// implementation specific.
    time_traceable: Option<bool>,

    /// The value of time-traceable shall be true if the
    /// frequency determining the timescale is traceable
    /// to a primary reference; otherwise, the value shall
    /// be false.
    /// The uncertainty specifications appropriate to the
    /// evaluation of whether traceability to a primary
    /// reference is achieved should be defined in the
    /// applicable PTP Profile. In the absence of such a
    /// definition the value of frequency-traceable is
    /// implementation specific.
    frequency_traceable: Option<bool>,

    /// If ptp-timescale is true, the timescale of
    /// the Grandmaster PTP Instance is PTP, which is
    /// the elapsed time since the PTP epoch measured
    /// using the second defined by International Atomic
    /// Time (TAI).
    /// If ptp-timescale is false, the timescale of
    /// the Grandmaster PTP Instance is ARB, which is
    /// the elapsed time since an arbitrary epoch.
    ptp_timescale: Option<bool>,

    /// The source of time used by the Grandmaster
    /// PTP Instance.
    time_source: Option<TimeSource>,

    /// If gptp_profile is true, use IEE 802.1AS (or gPTP) profile.
    gptp_profile: Option<bool>,
}

fn strip_prefix(input: &str) -> &str {
    input
        .strip_prefix("ieee1588-ptp-tt:")
        .map_or(input, |stripped| stripped)
}
