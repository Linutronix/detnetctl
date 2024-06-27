// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Helpers for BPF-based features
use crate::configuration::StreamIdentification;
use anyhow::{anyhow, Context, Result};
use libbpf_rs::{set_print, MapFlags, PrintLevel};
use std::collections::HashMap;

#[cfg(not(test))]
use libbpf_rs::Map;

#[cfg(test)]
pub(crate) mod mocks;
#[cfg(test)]
use crate::bpf::mocks::MockMap as Map;

impl StreamIdentification {
    /// Convert into fixed-size array
    ///
    /// # Errors
    /// Currently returns error if any of the attributes are None
    pub fn to_bytes(&self) -> Result<[u8; 8]> {
        let mut result: [u8; 8] = [0; 8];
        result[0..6].copy_from_slice(self.destination_address()?.as_bytes());
        result[6..8].copy_from_slice(&self.vid()?.to_ne_bytes());
        Ok(result)
    }
}

/// Defines how a BPF can be attached to an interface
pub trait Attacher<T> {
    /// Attach a BPF to the given interface and return the skel
    ///
    /// # Errors
    /// If attaching the BPF to the interface fails
    fn attach_interface(&mut self, interface: &str) -> Result<T>;
}

/// Manages BPF skels for interfaces
pub struct SkelManager<T> {
    skels: HashMap<String, T>,
    attacher: Box<dyn Attacher<T> + Send>,
}

impl<T> SkelManager<T> {
    /// Create a new `SkelManager`
    #[must_use]
    pub fn new(attacher: Box<dyn Attacher<T> + Send>) -> Self {
        set_print(Some((PrintLevel::Debug, print_to_log)));
        Self {
            skels: HashMap::default(),
            attacher,
        }
    }

    /// Call the given method with a BPF skel matching to the given interface
    /// If no BPF is attached to this interface, attach one first
    ///
    /// # Errors
    /// If no matching skel was found and/or attaching the BPF to the interface failed
    pub fn with_interface<F>(&mut self, interface: &str, f: F) -> Result<()>
    where
        F: FnOnce(&mut T) -> Result<()>,
    {
        if let Some(existing_interface) = self.skels.get_mut(interface) {
            f(existing_interface)
        } else {
            let skel = self
                .attacher
                .attach_interface(interface)
                .context("Failed to attach eBPF to interface")?;

            self.skels.insert(String::from(interface), skel);

            f(self
                .skels
                .get_mut(interface)
                .ok_or_else(|| anyhow!("Interface missing even after attach"))?)
        }
    }
}

#[allow(clippy::needless_pass_by_value)] // interface defined by libbpf-rs
fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => log::debug!("{}", msg),
        PrintLevel::Info => log::info!("{}", msg),
        PrintLevel::Warn => log::warn!("{}", msg),
    }
}

/// Find the stream with the given stream identification or add if it does not exist
///
/// # Result
/// The stream handle of the found/added stream
pub(crate) fn find_or_add_stream(
    streams: &Map,
    num_streams: &Map,
    stream_identification: &StreamIdentification,
    handle_from_bytes: impl FnOnce(Vec<u8>) -> Result<u16>,
) -> Result<u16> {
    let stream_id_bytes = stream_identification.to_bytes()?;

    // Check if stream already exists, otherwise calculate stream_handle from number of streams
    let mut adding_new_stream = false;
    let stream_handle = if let Some(s) = streams.lookup(&stream_id_bytes, MapFlags::ANY)? {
        handle_from_bytes(s)?
    } else {
        adding_new_stream = true;
        let num_streams = u16::from_ne_bytes(
            num_streams
                .lookup(&0_u32.to_ne_bytes(), MapFlags::ANY)?
                .ok_or_else(|| anyhow!("Cannot lookup number of streams"))?
                .try_into()
                .map_err(|_e| anyhow!("Invalid byte number"))?,
        );

        let max_streams: u16 = streams.info()?.info.max_entries.try_into()?;

        if num_streams == max_streams {
            return Err(anyhow!("Maximum number of streams reached"));
        }

        num_streams
    };

    if adding_new_stream {
        let new_num_streams = stream_handle + 1;

        num_streams.update(
            &0_u32.to_ne_bytes(),
            &new_num_streams.to_ne_bytes(),
            MapFlags::ANY,
        )?;
    }

    Ok(stream_handle)
}
