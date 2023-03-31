//! Installs filters to avoid interference between applications
//!
//! ```no_run
//! use detnetctl::guard::{Guard, BPFGuard};
//! let mut guard = BPFGuard::new();
//! guard.protect_priority("eth0", 5, 0x9e25b4d41b6c390b)?;
//! # Ok::<(), anyhow::Error>(())
//! ```
use anyhow::Result;

#[cfg(test)]
use mockall::automock;

/// Defines how to request interference protection
#[cfg_attr(test, automock)]
pub trait Guard {
    /// Install a filter only allowing sockets with the given token to transmit
    ///
    /// Messages for sockets sending to the same interface
    /// with the same priority will be dropped.
    fn protect_priority(&mut self, interface: &str, priority: u8, token: u64) -> Result<()>;
}

#[cfg(feature = "bpf")]
mod bpf;
#[cfg(feature = "bpf")]
pub use bpf::BPFGuard;

/// A guard doing nothing, but still providing the Guard trait
///
/// Useful for testing purposes (e.g. on kernels without the SO_TOKEN feature)
/// or if you only want to use other features without actually installing eBPFs.
#[derive(Default)]
pub struct DummyGuard;

impl DummyGuard {
    /// Create a new DummyGuard
    pub fn new() -> Self {
        DummyGuard::default()
    }
}

impl Guard for DummyGuard {
    fn protect_priority(&mut self, _interface: &str, _priority: u8, _token: u64) -> Result<()> {
        Ok(())
    }
}
