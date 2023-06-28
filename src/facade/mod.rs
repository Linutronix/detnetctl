// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Facade (currently via D-Bus) enabling secure access from application side
//!
//! ```
//! use detnetctl::controller::{Registration, Controller};
//! use detnetctl::configuration::{Configuration, YAMLConfiguration};
//! use detnetctl::facade::{Facade, Setup};
//! use detnetctl::queue_setup::{QueueSetup, DummyQueueSetup};
//! use detnetctl::guard::{Guard, DummyGuard};
//! use detnetctl::interface_setup::DummyInterfaceSetup;
//! use async_shutdown::Shutdown;
//! #
//! # #[path = "../configuration/doctest.rs"]
//! # mod doctest;
//! # let tmpfile = doctest::generate_example_yaml();
//! # let filepath = tmpfile.path();
//! #
//! # tokio_test::block_on(async {
//! use std::fs::File;
//! use std::sync::Arc;
//! use futures::lock::Mutex;
//!
//! let controller = Arc::new(Mutex::new(Controller::new()));
//! let shutdown = Shutdown::new();
//! let mut facade = Facade::new(shutdown.clone())?;
//! let mut configuration = Arc::new(Mutex::new(YAMLConfiguration::new()));
//! configuration.lock().await.read(File::open(filepath)?)?;
//! let mut queue_setup = Arc::new(Mutex::new(DummyQueueSetup::new(3)));
//! let mut guard = Arc::new(Mutex::new(DummyGuard::new()));
//! let mut interface_setup = Arc::new(Mutex::new(DummyInterfaceSetup::new()));
//!
//! facade.setup(Box::new(move |app_name| {
//!     let app_name = String::from(app_name);
//!     let cloned_controller = controller.clone();
//!     let cloned_configuration = configuration.clone();
//!     let cloned_queue_setup = queue_setup.clone();
//!     let cloned_guard = guard.clone();
//!     let cloned_interface_setup = interface_setup.clone();
//!     Box::pin(async move {
//!         cloned_controller.lock().await.register(
//!             &app_name,
//!             cloned_configuration,
//!             cloned_queue_setup,
//!             cloned_guard,
//!             cloned_interface_setup).await
//!     })
//! })).await?;
//! # Ok::<(), anyhow::Error>(())
//! # });
//! # Ok::<(), anyhow::Error>(())

use crate::controller::RegisterResponse;
use anyhow::Result;
use async_shutdown::Shutdown;
use async_trait::async_trait;
use std::future::Future;
use std::pin::Pin;

mod dbus;

type RegisterFuture = Pin<Box<dyn Future<Output = Result<RegisterResponse, anyhow::Error>> + Send>>;
type RegisterCallback = Box<dyn for<'a> FnMut(&'a str) -> RegisterFuture + Send>;

/// Setup of the facade
#[async_trait]
pub trait Setup {
    /// Setup the facade by providing a callback for the registration command
    async fn setup(&mut self, register: RegisterCallback) -> Result<()>;
}

/// Represents the D-Bus facade
pub struct Facade {
    dbus: dbus::DBus,
}

impl Facade {
    /// Create a new facade
    ///
    /// # Errors
    ///
    /// Will return `Err` if it was not possible to initialize the facade,
    /// e.g. due to problems connecting to D-Bus.
    pub fn new(shutdown: Shutdown) -> Result<Self> {
        Ok(Self {
            dbus: dbus::DBus::new(shutdown)?,
        })
    }
}

#[async_trait]
impl Setup for Facade {
    async fn setup(&mut self, register: RegisterCallback) -> Result<()> {
        self.dbus.setup(register).await?;
        Ok(())
    }
}
