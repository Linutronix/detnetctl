// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Main executable of detnetctl
// we do not want to panic or exit, see explanation in main()
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::expect_used,
        clippy::exit,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::modulo_arithmetic, // % 0 panics - use checked_rem
        clippy::integer_division,  // / 0 panics - use checked_div
        clippy::unreachable,
        clippy::unwrap_in_result,
    )
)]
#![allow(clippy::unnecessary_wraps)] // wraps are necessary for certain combinations of feature flags
extern crate detnetctl;

use anyhow::{anyhow, Error, Result};
use clap::Parser;

use futures::lock::Mutex;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

use detnetctl::configuration::{Configuration, YAMLConfiguration};
use detnetctl::controller::{Controller, Registration};
use detnetctl::dispatcher::{Dispatcher, DummyDispatcher};
use detnetctl::interface_setup::{DummyInterfaceSetup, InterfaceSetup};
use detnetctl::ptp::Ptp;
use detnetctl::queue_setup::{DummyQueueSetup, QueueSetup};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Oneshot registration with the provided app name and do not spawn D-Bus service
    #[arg(short, long)]
    app_name: Option<String>,

    /// Use YAML configuration with the provided file. Otherwise, uses sysrepo.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Skip queue setup and use the given priority for all streams
    #[arg(long, value_name = "PRIORITY")]
    no_queue_setup: Option<u32>,

    /// Skip installing eBPFs - no interference protection!
    #[arg(long)]
    no_dispatcher: bool,

    /// Print eBPF debug output to kernel tracing
    #[arg(long)]
    bpf_debug_output: bool,

    /// Skip setting up the link
    #[arg(long)]
    no_interface_setup: bool,

    /// Configure PTP for the given instance
    #[arg(short, long, value_name = "INSTANCE")]
    ptp_instance: Option<u32>,
}

#[tokio::main(flavor = "current_thread")]
/// Main function of `detnetctl`
///
/// # Errors
/// Will return `Err` if any error occurs that can not be handled.
/// Usually this should only happen during initialization, but
/// not when errors occur handling a certain request. In that case,
/// the error is printed and returned to the caller, but the program
/// does not crash to stay responsive and in a consistent state.
/// For the same reason, panic! is disencouraged in this codebase,
/// but still stopping of the execution in rare cases can not be
/// excluded (e.g. due to external crates). Therefore, make sure
/// a proper restart is configured (e.g. `Restart=` for `systemd`).
pub async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    let configuration = match cli.config {
        Some(file) => {
            let mut c = YAMLConfiguration::new();
            c.read(File::open(file)?)?;
            Arc::new(Mutex::new(c))
        }
        None => new_sysrepo_config()?,
    };

    let ptp_manager = new_ptp_manager();
    if let Some(identity) = cli.ptp_instance {
        if let Some(mgr) = &ptp_manager {
            mgr.lock()
                .await
                .apply_config(&configuration.lock().await.get_ptp_config(identity)?)
                .await?;
        } else {
            return Err(anyhow!("ptp feature not built in!"));
        }
    }

    let queue_setup = match cli.no_queue_setup {
        Some(priority) => Arc::new(Mutex::new(DummyQueueSetup::new(priority))),
        None => new_detd_gateway()?,
    };

    let dispatcher = if cli.no_dispatcher {
        Arc::new(Mutex::new(DummyDispatcher))
    } else {
        new_bpf_dispatcher(cli.bpf_debug_output)?
    };

    let interface_setup = if cli.no_interface_setup {
        Arc::new(Mutex::new(DummyInterfaceSetup))
    } else {
        new_netinterface_setup()?
    };

    let controller = Controller::new();

    match cli.app_name {
        Some(app_name) => {
            let response = controller
                .register(
                    &app_name,
                    configuration,
                    queue_setup,
                    dispatcher,
                    interface_setup,
                )
                .await?;
            println!("Final result: {response:#?}");
        }
        None => {
            spawn_dbus_service(
                Arc::new(Mutex::new(controller)),
                configuration,
                queue_setup,
                dispatcher,
                interface_setup,
                ptp_manager,
            )
            .await?;
        }
    }

    Ok(())
}

#[allow(dead_code)] // will not be used if ALL features are enabled
fn feature_missing_error(feature: &str, alternative: &str) -> Error {
    anyhow!("{} feature is not built in!\nYou can still use {} if appropriate for your use case or rebuild with the feature enabled!", feature, alternative)
}

#[cfg(feature = "dbus")]
use {
    async_shutdown::Shutdown,
    detnetctl::facade::{
        Facade, PtpStatusCallback, PtpStatusFuture, RegisterCallback, RegisterFuture, Setup,
    },
    tokio::signal,
};
#[cfg(feature = "dbus")]
async fn spawn_dbus_service(
    controller: Arc<Mutex<Controller>>,
    configuration: Arc<Mutex<dyn Configuration + Send>>,
    queue_setup: Arc<Mutex<dyn QueueSetup + Send>>,
    dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
    interface_setup: Arc<Mutex<dyn InterfaceSetup + Sync + Send>>,
    ptp: Option<Arc<Mutex<dyn Ptp + Sync + Send>>>,
) -> Result<()> {
    let shutdown = Shutdown::new();
    let mut facade = Facade::new(shutdown.clone())?;

    let register_callback: RegisterCallback = Box::new(move |app_name| -> RegisterFuture {
        let app_name = String::from(app_name);
        let cloned_controller = controller.clone();
        let cloned_configuration = configuration.clone();
        let cloned_queue_setup = queue_setup.clone();
        let cloned_dispatcher = dispatcher.clone();
        let cloned_interface_setup = interface_setup.clone();
        Box::pin(async move {
            cloned_controller
                .lock()
                .await
                .register(
                    &app_name,
                    cloned_configuration,
                    cloned_queue_setup,
                    cloned_dispatcher,
                    cloned_interface_setup,
                )
                .await
        })
    });

    let ptp_callback = ptp.map(|ptp_manager| -> PtpStatusCallback {
        Box::new(
            move |interface, max_clock_delta, max_master_offset| -> PtpStatusFuture {
                let interface = String::from(interface);
                let cloned_ptp = ptp_manager.clone();
                Box::pin(async move {
                    cloned_ptp
                        .lock()
                        .await
                        .get_status(&interface, max_clock_delta, max_master_offset)
                        .await
                })
            },
        )
    });

    facade.setup(register_callback, ptp_callback).await?;

    println!("Started detnetctl");

    // Wait for shutdown
    match shutdown.wrap_cancel(signal::ctrl_c()).await {
        Some(Ok(())) | None => {}
        Some(Err(err)) => {
            eprintln!("listening to shutdown signal failed: {err}");
            // we also shut down in case of error
        }
    }

    shutdown.shutdown();
    shutdown.wait_shutdown_complete().await;

    Ok(())
}

#[cfg(not(feature = "dbus"))]
#[allow(clippy::unused_async)]
async fn spawn_dbus_service(
    _controller: Arc<Mutex<Controller>>,
    _configuration: Arc<Mutex<dyn Configuration + Send>>,
    _queue_setup: Arc<Mutex<dyn QueueSetup + Send>>,
    _dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
    _interface_setup: Arc<Mutex<dyn InterfaceSetup + Sync + Send>>,
    _ptp: Option<Arc<Mutex<dyn Ptp + Sync + Send>>>,
) -> Result<()> {
    Err(feature_missing_error("dbus", "--app-name"))
}

#[cfg(feature = "bpf")]
use detnetctl::dispatcher::BPFDispatcher;
#[cfg(feature = "bpf")]
fn new_bpf_dispatcher(debug_output: bool) -> Result<Arc<Mutex<dyn Dispatcher + Send>>> {
    Ok(Arc::new(Mutex::new(BPFDispatcher::new(debug_output))))
}

#[cfg(not(feature = "bpf"))]
fn new_bpf_dispatcher(_debug_output: bool) -> Result<Arc<Mutex<dyn Dispatcher + Send>>> {
    Err(feature_missing_error("bpf", "--no-dispatcher"))
}

#[cfg(feature = "sysrepo")]
use detnetctl::configuration::SysrepoConfiguration;
#[cfg(feature = "sysrepo")]
fn new_sysrepo_config() -> Result<Arc<Mutex<dyn Configuration + Send>>> {
    Ok(Arc::new(Mutex::new(SysrepoConfiguration::new()?)))
}

#[cfg(not(feature = "sysrepo"))]
fn new_sysrepo_config() -> Result<Arc<Mutex<dyn Configuration + Send>>> {
    Err(feature_missing_error("sysrepo", "--config"))
}

#[cfg(feature = "detd")]
use detnetctl::queue_setup::DetdGateway;
#[cfg(feature = "detd")]
fn new_detd_gateway() -> Result<Arc<Mutex<dyn QueueSetup + Send>>> {
    Ok(Arc::new(Mutex::new(DetdGateway::new(None, None))))
}

#[cfg(not(feature = "detd"))]
fn new_detd_gateway() -> Result<Arc<Mutex<dyn QueueSetup + Send>>> {
    Err(feature_missing_error("detd", "--no-queue-setup"))
}

#[cfg(feature = "netlink")]
use detnetctl::interface_setup::NetlinkSetup;
#[cfg(feature = "netlink")]
fn new_netinterface_setup() -> Result<Arc<Mutex<dyn InterfaceSetup + Sync + Send>>> {
    Ok(Arc::new(Mutex::new(NetlinkSetup::new())))
}

#[cfg(not(feature = "netlink"))]
fn new_netinterface_setup() -> Result<Arc<Mutex<dyn InterfaceSetup + Sync + Send>>> {
    Err(feature_missing_error("netlink", "--no-interface-setup"))
}

#[cfg(feature = "ptp")]
use detnetctl::ptp::PtpManager;
#[cfg(feature = "ptp")]
fn new_ptp_manager() -> Option<Arc<Mutex<dyn Ptp + Sync + Send>>> {
    Some(Arc::new(Mutex::new(PtpManager::new())))
}

#[cfg(not(feature = "ptp"))]
fn new_ptp_manager() -> Option<Arc<Mutex<dyn Ptp + Sync + Send>>> {
    None
}
