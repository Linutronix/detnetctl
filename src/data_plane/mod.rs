// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Data plane for handling packets like bridging and routing
#![cfg_attr(not(feature = "bpf"), doc = "```ignore")]
#![cfg_attr(feature = "bpf", doc = "```no_run")]
//! use detnetctl::configuration::{FillDefaults, StreamBuilder,
//!                                StreamIdentificationBuilder,
//!                                OutgoingL2Builder};
//! use detnetctl::data_plane::{DataPlane, BpfDataPlane};
//! use std::path::Path;
//! let mut data_plane = BpfDataPlane::new(false);
//! let stream_config = StreamBuilder::new()
//!     .identifications(vec![
//!       StreamIdentificationBuilder::new()
//!       .destination_address("CB:CB:CB:CB:CB:CB".parse()?)
//!       .vid(5)
//!       .build()]
//!     )
//!     .outgoing_l2(vec![OutgoingL2Builder::new()
//!       .outgoing_interface("eth0".to_owned())
//!       .build()])
//!       .build();
//!
//! data_plane.setup_stream(&stream_config)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use crate::configuration::detnet::Flow;
use crate::configuration::Stream;
use anyhow::Result;
use std::path::Path;

#[cfg(test)]
use mockall::automock;

/// Defines how to request interference protection
#[cfg_attr(test, automock)]
pub trait DataPlane {
    /// Setup the TSN stream according to the provided configuration.
    ///
    /// # Errors
    ///
    /// Will return `Err` if it was not possible to install a data plane,
    /// e.g. if the interface does not exist or there was a conflict
    /// creating the eBPF hook.
    fn setup_stream(&mut self, stream_config: &Stream) -> Result<()>;

    /// Setup the DetNet flow according to the provided configuration.
    ///
    /// # Errors
    ///
    /// Will return `Err` if it was not possible to install a data plane,
    /// e.g. if the interface does not exist or there was a conflict
    /// creating the eBPF hook.
    fn setup_flow(&mut self, flow_config: &Flow) -> Result<()>;

    /// Load a dummy XDP program that just lets all traffic pass
    /// This is for enabling redirection to interfaces that
    /// otherwise will not initialize their XDP.
    ///
    /// # Errors
    ///
    /// Will return `Err` if it was not possible to install a data plane,
    /// e.g. if the interface does not exist or there was a conflict
    /// creating the eBPF hook.
    fn load_xdp_pass(&mut self, interface: &str) -> Result<()>;

    /// Pin a dummy XDP program that just lets all traffic pass
    /// Similar to `load_xdp_pass`, but just pins the program
    /// and does not attach it. This allows to attach it via
    /// the ip tool in a different namespace.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the program could not be loaded or pinned.
    fn pin_xdp_pass(&mut self, path: &Path) -> Result<()>;
}

#[cfg(feature = "bpf")]
mod bpf;
#[cfg(feature = "bpf")]
pub use bpf::BpfDataPlane;

/// A data plane doing nothing, but still providing the `DataPlane` trait
///
/// Useful for testing purposes or if you only want to use other features without actually installing eBPFs.
pub struct DummyDataPlane;

impl DataPlane for DummyDataPlane {
    fn setup_stream(&mut self, _stream_config: &Stream) -> Result<()> {
        Ok(())
    }

    fn setup_flow(&mut self, _flow_config: &Flow) -> Result<()> {
        Ok(())
    }

    fn load_xdp_pass(&mut self, _interface: &str) -> Result<()> {
        Ok(())
    }

    fn pin_xdp_pass(&mut self, _path: &Path) -> Result<()> {
        Ok(())
    }
}
