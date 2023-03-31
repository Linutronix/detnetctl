//! Facade (currently via D-Bus) enabling secure access from application side
//!
//! ```
//! use detnetctl::controller::{Registration, Controller};
//! use detnetctl::configuration::{Configuration, YAMLConfiguration};
//! use detnetctl::facade::{Facade, Setup};
//! use detnetctl::nic_setup::{NICSetup, DummyNICSetup};
//! use detnetctl::guard::{Guard, DummyGuard};
//! use async_shutdown::Shutdown;
//! #
//! # #[path = "../configuration/doctest.rs"]
//! # mod doctest;
//! # let tmpfile = doctest::generate_example_yaml();
//! # let filepath = tmpfile.path();
//! #
//! # tokio_test::block_on(async {
//! use std::fs::File;
//! let controller = Controller::new();
//! let shutdown = Shutdown::new();
//! let mut facade = Facade::new(shutdown.clone())?;
//! let mut configuration = YAMLConfiguration::new();
//! configuration.read(File::open(filepath)?)?;
//! let mut nic_setup = DummyNICSetup::new(3);
//! let mut guard = DummyGuard::new();
//!
//! facade.setup(Box::new(move |app_name| {
//!     controller.register(app_name, &mut configuration, &mut nic_setup, &mut guard)
//! })).await?;
//! # Ok::<(), anyhow::Error>(())
//! # });
//! # Ok::<(), anyhow::Error>(())

use crate::controller::RegisterResponse;
use anyhow::Result;
use async_shutdown::Shutdown;
use async_trait::async_trait;

mod dbus;

/// Setup of the facade
#[async_trait]
pub trait Setup {
    /// Setup the facade by providing a callback for the registration command
    async fn setup(
        &mut self,
        register: Box<dyn for<'a> FnMut(&'a str) -> Result<RegisterResponse> + Send>,
    ) -> Result<()>;
}

/// Represents the D-Bus facade
pub struct Facade {
    dbus: dbus::DBus,
}

impl Facade {
    /// Create a new facade
    pub fn new(shutdown: Shutdown) -> Result<Self> {
        Ok(Facade {
            dbus: dbus::DBus::new(shutdown)?,
        })
    }
}

#[async_trait]
impl Setup for Facade {
    async fn setup(
        &mut self,
        register: Box<dyn for<'a> FnMut(&'a str) -> Result<RegisterResponse> + Send>,
    ) -> Result<()> {
        self.dbus.setup(register).await?;
        Ok(())
    }
}
