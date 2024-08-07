// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Dispatches TSN streams into queues and protects against interference between applications
#![cfg_attr(not(feature = "bpf"), doc = "```ignore")]
#![cfg_attr(feature = "bpf", doc = "```no_run")]
//! use detnetctl::configuration::StreamIdentificationBuilder;
//! use detnetctl::dispatcher::{Dispatcher, BPFDispatcher, Protection};
//! use std::path::Path;
//! let mut dispatcher = BPFDispatcher::new(false);
//! let cgroup = Path::new("/sys/fs/cgroup/system.slice/some.service/");
//! let stream_id = StreamIdentificationBuilder::new()
//!     .destination_address("CB:CB:CB:CB:CB:CB".parse()?)
//!     .vid(5)
//!     .build();
//!
//! dispatcher.configure_stream("eth0", &stream_id, Some(5), Some(3),
//!                             Protection {
//!                                 cgroup: Some(cgroup.into()),
//!                                 drop_all: false,
//!                                 drop_without_sk: false,
//!                             })?;
//!
//! # Ok::<(), anyhow::Error>(())
//! ```

use crate::configuration::StreamIdentification;
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;

#[cfg(test)]
use mockall::automock;

/// Define the level of protection for this stream
pub struct Protection {
    /// Drop all egress traffic for this stream.
    pub drop_all: bool,

    /// Drop all egress traffic that is not associated to a socket.
    pub drop_without_sk: bool,

    /// Drop egress traffic with associated socket which is not under the given cgroup.
    /// Traffic without associated socket is permitted unless `drop_without_sk` is true.
    pub cgroup: Option<Arc<Path>>,
}

/// Defines how to request interference protection
#[cfg_attr(test, automock)]
pub trait Dispatcher {
    /// Configure a stream
    /// Traffic identified with the provided `stream_identification` will get assigned the provided
    /// priority (and thus the corresponding queue and finally the timeslot).
    ///
    /// If cgroup is provided, only sockets with the given cgroup can send traffic to this stream,
    /// other traffic gets dropped.
    ///
    /// # Errors
    ///
    /// Will return `Err` if it was not possible to install a dispatcher,
    /// e.g. if the interface does not exist or there was a conflict
    /// creating the eBPF hook.
    fn configure_stream(
        &mut self,
        interface: &str,
        stream_identification: &StreamIdentification,
        priority: Option<u32>,
        pcp: Option<u8>,
        protection: Protection,
    ) -> Result<()>;

    /// Protect a stream
    /// Traffic identified with the provided `stream_identification` will
    /// be protected by only allowing applications in the provided cgroup.
    ///
    /// # Errors
    ///
    /// Will return `Err` if it was not possible to protect the stream,
    /// e.g. if it does not exist yet.
    fn protect_stream(
        &mut self,
        interface: &str,
        stream_identification: &StreamIdentification,
        protection: Protection,
    ) -> Result<()>;

    /// Configure best-effort traffic
    /// All traffic that can not be classified into one of the other streams is classified as
    /// best-effort traffic.
    /// Per convention, `stream_handle` 0 corresponds to best-effort traffic and is initally
    /// configured with priority 0 and empty cgroup.
    ///
    /// If cgroup is provided, only sockets with the given cgroup can send traffic to this stream,
    /// other traffic gets dropped. That should generally be avoided for the best-effort class,
    /// otherwise even kernel traffic will not be sent properly (e.g. ARP messages).
    ///
    /// # Errors
    ///
    /// Will return `Err` if it was not possible to install a dispatcher,
    /// e.g. if the interface does not exist or there was a conflict
    /// creating the eBPF hook.
    fn configure_best_effort(
        &mut self,
        interface: &str,
        priority: u32,
        protection: Protection,
    ) -> Result<()>;
}

#[cfg(feature = "bpf")]
mod bpf;
#[cfg(feature = "bpf")]
pub use bpf::BPFDispatcher;

/// A dispatcher doing nothing, but still providing the Dispatcher trait
///
/// Useful for testing purposes or if you only want to use other features without actually installing eBPFs.
pub struct DummyDispatcher;

impl Dispatcher for DummyDispatcher {
    fn configure_stream(
        &mut self,
        _interface: &str,
        _stream_identification: &StreamIdentification,
        _priority: Option<u32>,
        _pcp: Option<u8>,
        _protection: Protection,
    ) -> Result<()> {
        Ok(())
    }

    fn protect_stream(
        &mut self,
        _interface: &str,
        _stream_identification: &StreamIdentification,
        _protection: Protection,
    ) -> Result<()> {
        Ok(())
    }

    fn configure_best_effort(
        &mut self,
        _interface: &str,
        _priority: u32,
        _protection: Protection,
    ) -> Result<()> {
        Ok(())
    }
}
