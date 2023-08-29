// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Facade (currently via D-Bus) enabling secure access from application side
//!
//! ## D-Bus Interface
//!
//! ### org.detnet.detnetctl.Register
//!
//! ```markdown
//! Register(app_name: string, cgroup: string) -> (interface: string)
//! ```
//!
//! The caller needs to be owner of `org.detnet.apps.{app_name}`. Otherwise, the method call is
//! rejected. Together with a corresponding D-Bus policy, this only allows a permitted application
//! to register a DetNet application.
//!
//! #### Parameters
//! * **app_name**: The name of the app to register. Matches the app name in the configuration.
//! * **cgroup**: The cgroup that should be allowed to generate traffic for this app.
//!               Provide as path rooted in the cgroup fs as it is also provided by /proc/\<PID\>/cgroup,
//!               e.g. /user.slice/user-1001.slice/user@1001.service/app.slice/detnetctl.app0.scope
//!
//! #### Returns
//! * **interface**: The name of the (virtual) interface to use for setting up the socket.
//!
//! ### org.detnet.detnetctl.PtpStatus
//!
//! ```markdown
//! PtpStatus(interface: string, max_clock_delta_ns: u64, max_master_offset_ns: u64)
//! -> (issues: u8, phc_rt: int64, phc_tai: int64, kernel_tai_offset: int32, port_state: u8, master_offset: int64)
//! ```
//!
//! #### Parameters
//! * **interface**: Network interface to request the status for (e.g. eth0)
//! * **max_clock_delta_ns**: A larger clock delta in nanoseconds will indicate an issue (a common value is 50000)
//! * **max_master_offset_ns**: A larger master clock offset in nanoseconds will indicate an issue (a common value is 100)
//!
//! #### Returns
//! * **issues**: Bitfield covering various possible PTP issues.
//!     + 0b00000001 - phc-rt delta is not near to the UTC offset (more than +-max_clock_delta_ns off)
//!     + 0b00000010 - phc-tai is too large (more than +-max_clock_delta_ns)
//!     + 0b00000100 - UTC-TAI offset configured in the kernel does not match
//!     + 0b00001000 - Port state is not master, slave or grand master
//!     + 0b00010000 - Master offset too large (more than max_master_offset_ns)
//! * **phc_rt**: PTP Clock minus CLOCK_REALTIME
//! * **phc_tai**: PTP Clock minus CLOCK_TAI
//! * **kernel_tai_offset**: UTC-TAI offset configured in the kernel
//! * **port_state**: State of the PTP port
//!     + 1 - Initializing
//!     + 2 - Faulty
//!     + 3 - Disabled
//!     + 4 - Listening
//!     + 5 - PreMaster
//!     + 6 - Master
//!     + 7 - Passive
//!     + 8 - Uncalibrated
//!     + 9 - Slave
//!     + 10 - GrandMaster
//! * **master_offset**: PTP master offset
//!
//! ## Usage Example of the Facade Module within detnetctl
#![cfg_attr(not(feature = "ptp"), doc = "```ignore")]
#![cfg_attr(feature = "ptp", doc = "```")]
//! use detnetctl::controller::{Registration, Controller};
//! use detnetctl::configuration::{Configuration, YAMLConfiguration};
//! use detnetctl::facade::{Facade, Setup};
//! use detnetctl::queue_setup::{QueueSetup, DummyQueueSetup};
//! use detnetctl::dispatcher::{Dispatcher, DummyDispatcher};
//! use detnetctl::interface_setup::DummyInterfaceSetup;
//! use detnetctl::ptp::{Ptp, PtpManager};
//! use async_shutdown::Shutdown;
//! #
//! # #[path = "../configuration/doctest.rs"]
//! # mod doctest;
//! # let tmpfile = doctest::generate_example_yaml();
//! # let filepath = tmpfile.path();
//! #
//! # tokio_test::block_on(async {
//! use std::fs::File;
//! use std::path::PathBuf;
//! use std::sync::Arc;
//! use futures::lock::Mutex;
//!
//! let controller = Arc::new(Mutex::new(Controller::new()));
//! let shutdown = Shutdown::new();
//! let mut facade = Facade::new(shutdown.clone())?;
//! let mut configuration = Arc::new(Mutex::new(YAMLConfiguration::new()));
//! configuration.lock().await.read(File::open(filepath)?)?;
//! let mut queue_setup = Arc::new(Mutex::new(DummyQueueSetup::new(3)));
//! let mut dispatcher = Arc::new(Mutex::new(DummyDispatcher));
//! let mut interface_setup = Arc::new(Mutex::new(DummyInterfaceSetup));
//! let mut ptp = Arc::new(Mutex::new(PtpManager::new()));
//!
//! facade.setup(
//!     Box::new(move |app_name,cgroup| {
//!         let app_name = String::from(app_name);
//!         let cgroup = PathBuf::from(cgroup);
//!         let cloned_controller = controller.clone();
//!         let cloned_configuration = configuration.clone();
//!         let cloned_queue_setup = queue_setup.clone();
//!         let cloned_dispatcher = dispatcher.clone();
//!         let cloned_interface_setup = interface_setup.clone();
//!         Box::pin(async move {
//!             cloned_controller.lock().await.register(
//!                 &app_name,
//!                 &cgroup,
//!                 cloned_configuration,
//!                 cloned_queue_setup,
//!                 cloned_dispatcher,
//!                 cloned_interface_setup).await
//!         })
//!     }),
//!     Some(Box::new(move |interface,max_clock_delta,max_master_offset| {
//!         let interface = String::from(interface);
//!         let cloned_ptp = ptp.clone();
//!         Box::pin(async move {
//!             cloned_ptp.lock().await.get_status(&interface,max_clock_delta,max_master_offset).await
//!         })
//!     })),
//! ).await?;
//! # Ok::<(), anyhow::Error>(())
//! # });
//! # Ok::<(), anyhow::Error>(())

use crate::controller::RegisterResponse;
use crate::ptp;
use anyhow::Result;
use async_shutdown::Shutdown;
use async_trait::async_trait;
use chrono::Duration;
use std::future::Future;
use std::pin::Pin;

mod dbus;

/// Future to await for registration
pub type RegisterFuture =
    Pin<Box<dyn Future<Output = Result<RegisterResponse, anyhow::Error>> + Send>>;
/// Returns a future to await for registration
pub type RegisterCallback = Box<dyn for<'a> FnMut(&'a str, &'a str) -> RegisterFuture + Send>;

/// Future to await to get the PTP status
pub type PtpStatusFuture =
    Pin<Box<dyn Future<Output = Result<ptp::PtpStatus, anyhow::Error>> + Send>>;
/// Returns a future to await to get the PTP status
pub type PtpStatusCallback =
    Box<dyn for<'a> FnMut(&'a str, Duration, Duration) -> PtpStatusFuture + Send>;

/// Setup of the facade
#[async_trait]
pub trait Setup {
    /// Setup the facade by providing a callback for the registration command
    async fn setup(
        &mut self,
        register: RegisterCallback,
        get_ptp_status: Option<PtpStatusCallback>,
    ) -> Result<()>;
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
    async fn setup(
        &mut self,
        register: RegisterCallback,
        get_ptp_status: Option<PtpStatusCallback>,
    ) -> Result<()> {
        self.dbus.setup(register, get_ptp_status).await?;
        Ok(())
    }
}
