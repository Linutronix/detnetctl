// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Dispatches TSN streams into queues and protects against interference between applications
#![cfg_attr(not(feature = "bpf"), doc = "```ignore")]
#![cfg_attr(feature = "bpf", doc = "```no_run")]
//! use detnetctl::dispatcher::{Dispatcher, BPFDispatcher, StreamIdentification};
//! let mut dispatcher = BPFDispatcher::new(false);
//! let stream_id = StreamIdentification {
//!     destination_address: "CB:CB:CB:CB:CB:CB".parse()?,
//!     vlan_identifier: 5
//! };
//! dispatcher.configure_stream("eth0", &stream_id, 5, 3, Some(0x9e25b4d41b6c390b))?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use anyhow::Result;
use eui48::MacAddress;

#[cfg(test)]
use mockall::automock;

/// Stream identification
/// Currently only IEEE 802.1CB-2017 null stream identification is supported
#[derive(Debug)]
pub struct StreamIdentification {
    /// Destination MAC address
    pub destination_address: MacAddress,

    /// VLAN Identifier
    pub vlan_identifier: u16,
}

impl StreamIdentification {
    /// Convert into fixed-size array
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut result: [u8; 8] = [0; 8];
        result[0..6].copy_from_slice(self.destination_address.as_bytes());
        result[6..8].copy_from_slice(&self.vlan_identifier.to_ne_bytes());
        result
    }
}

/// Defines how to request interference protection
#[cfg_attr(test, automock)]
pub trait Dispatcher {
    /// Configure a stream
    /// Traffic identified with the provided `stream_identification` will get assigned the provided
    /// priority (and thus the corresponding queue and finally the timeslot).
    ///
    /// If token is provided, only sockets with the given token can send traffic to this stream,
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
        priority: u32,
        pcp: u8,
        token: Option<u64>,
    ) -> Result<()>;

    /// Configure best-effort traffic
    /// All traffic that can not be classified into one of the other streams is classified as
    /// best-effort traffic.
    /// Per convention, `stream_handle` 0 corresponds to best-effort traffic and is initally
    /// configured with priority 0 and empty token.
    ///
    /// If token is provided, only sockets with the given token can send traffic to this stream,
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
        token: Option<u64>,
    ) -> Result<()>;
}

#[cfg(feature = "bpf")]
mod bpf;
#[cfg(feature = "bpf")]
pub use bpf::BPFDispatcher;

/// A dispatcher doing nothing, but still providing the Dispatcher trait
///
/// Useful for testing purposes (e.g. on kernels without the `SO_TOKEN` feature)
/// or if you only want to use other features without actually installing eBPFs.
pub struct DummyDispatcher;

impl Dispatcher for DummyDispatcher {
    fn configure_stream(
        &mut self,
        _interface: &str,
        _stream_identification: &StreamIdentification,
        _priority: u32,
        _pcp: u8,
        _token: Option<u64>,
    ) -> Result<()> {
        Ok(())
    }

    fn configure_best_effort(
        &mut self,
        _interface: &str,
        _priority: u32,
        _token: Option<u64>,
    ) -> Result<()> {
        Ok(())
    }
}
