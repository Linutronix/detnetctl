// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

//! Main executable of detnetctl
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

use anyhow::{anyhow, Error, Result};
use clap::Parser;

use futures::lock::Mutex;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

use detnetctl::configuration::{Configuration, MergedConfiguration, YAMLConfiguration};
use detnetctl::controller::{Controller, Setup};
use detnetctl::dispatcher::{Dispatcher, DummyDispatcher};
use detnetctl::interface_setup::{DummyInterfaceSetup, InterfaceSetup};
use detnetctl::ptp::Ptp;
use detnetctl::queue_setup::{DummyQueueSetup, QueueSetup};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[allow(clippy::struct_excessive_bools)]
struct Cli {
    /// Oneshot setup, i.e. do not spawn D-Bus service
    #[arg(short, long)]
    oneshot: bool,

    /// Skip queue setup
    #[arg(long)]
    no_queue_setup: bool,

    /// Skip installing eBPFs - no interference protection!
    #[arg(long)]
    no_dispatcher: bool,

    /// Print eBPF debug output to kernel tracing
    #[arg(long)]
    bpf_debug_output: bool,

    /// Skip setting up the link
    #[arg(long)]
    no_interface_setup: bool,

    /// Skip PTP configuration
    #[arg(long)]
    no_ptp_config: bool,

    /// Load Sysrepo configuration
    #[arg(short, long)]
    sysrepo: bool,

    /// YAML configuration file. Mandatory if --sysrepo is not provided. If both is provided, configuration of file and sysrepo is merged.
    #[arg(value_name = "FILE", required_unless_present = "sysrepo")]
    config: Option<PathBuf>,
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
///
/// # Panics
/// The only known case is when the tokio runtime can not even be started
/// before calling the actual main function.
pub async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    let configuration: Arc<Mutex<dyn Configuration + Send>> = if let Some(file) = cli.config {
        let mut yaml_configuration = YAMLConfiguration::new();
        yaml_configuration.read(File::open(file)?)?;

        if cli.sysrepo {
            Arc::new(Mutex::new(MergedConfiguration::new(
                new_sysrepo_config_box()?,
                Box::new(yaml_configuration),
            )))
        } else {
            Arc::new(Mutex::new(yaml_configuration))
        }
    } else {
        new_sysrepo_config_arc_mutex()?
    };

    let ptp_manager = new_ptp_manager();
    let ptp_active_instance = configuration.lock().await.get_ptp_active_instance()?;
    if !cli.no_ptp_config {
        if let Some(instance) = ptp_active_instance {
            if let Some(mgr) = &ptp_manager {
                mgr.lock()
                    .await
                    .apply_config(
                        &configuration
                            .lock()
                            .await
                            .get_ptp_config(instance)?
                            .ok_or_else(|| {
                                anyhow!("No PTP config found for instance {instance}")
                            })?,
                    )
                    .await?;
            } else {
                return Err(feature_missing_error("ptp", "--no-ptp-config"));
            }
        }
    }

    let queue_setup = if cli.no_queue_setup {
        Arc::new(Mutex::new(DummyQueueSetup))
    } else {
        new_taprio_setup()?
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

    // Setup the system for all configured applications
    controller
        .setup(
            configuration.clone(),
            queue_setup.clone(),
            dispatcher.clone(),
            interface_setup.clone(),
        )
        .await?;

    // Spawn D-Bus service if requested
    if !cli.oneshot {
        spawn_dbus_service(
            Arc::new(Mutex::new(controller)),
            configuration,
            dispatcher,
            ptp_manager,
        )
        .await?;
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
    detnetctl::controller::Protect,
    detnetctl::facade::{
        Facade, ProtectCallback, ProtectFuture, PtpStatusCallback, PtpStatusFuture,
        Setup as FacadeSetup,
    },
    tokio::signal,
};
#[cfg(feature = "dbus")]
async fn spawn_dbus_service(
    controller: Arc<Mutex<Controller>>,
    configuration: Arc<Mutex<dyn Configuration + Send>>,
    dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
    ptp: Option<Arc<Mutex<dyn Ptp + Sync + Send>>>,
) -> Result<()> {
    let shutdown = Shutdown::new();
    let mut facade = Facade::new(shutdown.clone())?;

    let protect_callback: ProtectCallback = Box::new(move |app_name, cgroup| -> ProtectFuture {
        let app_name = String::from(app_name);
        let cgroup = PathBuf::from(cgroup);
        let cloned_controller = controller.clone();
        let cloned_configuration = configuration.clone();
        let cloned_dispatcher = dispatcher.clone();
        Box::pin(async move {
            cloned_controller
                .lock()
                .await
                .protect(&app_name, &cgroup, cloned_configuration, cloned_dispatcher)
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

    facade.setup(protect_callback, ptp_callback).await?;

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
    _dispatcher: Arc<Mutex<dyn Dispatcher + Send>>,
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
fn new_sysrepo_config_box() -> Result<Box<dyn Configuration + Send>> {
    Ok(Box::new(SysrepoConfiguration::new()?))
}
#[cfg(feature = "sysrepo")]
fn new_sysrepo_config_arc_mutex() -> Result<Arc<Mutex<dyn Configuration + Send>>> {
    Ok(Arc::new(Mutex::new(SysrepoConfiguration::new()?)))
}

#[cfg(not(feature = "sysrepo"))]
fn new_sysrepo_config_box() -> Result<Box<dyn Configuration + Send>> {
    Err(feature_missing_error("sysrepo", "a YAML file"))
}
#[cfg(not(feature = "sysrepo"))]
fn new_sysrepo_config_arc_mutex() -> Result<Arc<Mutex<dyn Configuration + Send>>> {
    Err(feature_missing_error("sysrepo", "a YAML file"))
}

#[cfg(feature = "netlink")]
use detnetctl::queue_setup::TaprioSetup;
#[cfg(feature = "netlink")]
fn new_taprio_setup() -> Result<Arc<Mutex<dyn QueueSetup + Send>>> {
    Ok(Arc::new(Mutex::new(TaprioSetup)))
}

#[cfg(not(feature = "netlink"))]
fn new_taprio_setup() -> Result<Arc<Mutex<dyn QueueSetup + Send>>> {
    Err(feature_missing_error("netlink", "--no-queue-setup"))
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
