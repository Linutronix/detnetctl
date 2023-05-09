extern crate detnetctl;

use anyhow::{anyhow, Error, Result};
use clap::Parser;
use futures::lock::Mutex;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

use detnetctl::configuration::{Configuration, YAMLConfiguration};
use detnetctl::controller::{Controller, Registration};
use detnetctl::guard::{DummyGuard, Guard};
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

    /// Skip queue setup and return the given PRIORITY
    #[arg(long, value_name = "PRIORITY")]
    no_queue_setup: Option<u8>,

    /// Skip installing eBPFs - no interference protection!
    #[arg(long)]
    no_guard: bool,

    /// Print eBPF debug output to kernel tracing
    #[arg(long)]
    bpf_debug_output: bool,
}

#[tokio::main(flavor = "current_thread")]
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

    let queue_setup = match cli.no_queue_setup {
        Some(priority) => Arc::new(Mutex::new(DummyQueueSetup::new(priority))),
        None => new_detd_gateway()?,
    };

    let guard = match cli.no_guard {
        true => Arc::new(Mutex::new(DummyGuard::new())),
        false => new_bpf_guard(cli.bpf_debug_output)?,
    };

    let controller = Controller::new();

    match cli.app_name {
        Some(app_name) => {
            let response = controller
                .register(
                    &app_name,
                    configuration,
                    queue_setup,
                    guard,
                )
                .await?;
            println!("Final result: {:#?}", response);
        }
        None => {
            spawn_dbus_service(
                Arc::new(Mutex::new(controller)),
                configuration,
                queue_setup,
                guard,
            )
            .await?
        }
    }

    Ok(())
}

#[allow(dead_code)] // will not be used if ALL features are enabled
fn feature_missing_error(feature: &str, alternative: &str) -> Error {
    anyhow!("{} features is not built in!\nYou can still use {} if appropriate for your use case or rebuild with the feature enabled!", feature, alternative)
}

#[cfg(feature = "dbus")]
use {
    async_shutdown::Shutdown,
    detnetctl::facade::{Facade, Setup},
    tokio::signal,
};
#[cfg(feature = "dbus")]
async fn spawn_dbus_service(
    controller: Arc<Mutex<Controller>>,
    configuration: Arc<Mutex<dyn Configuration + Send>>,
    queue_setup: Arc<Mutex<dyn QueueSetup + Send>>,
    guard: Arc<Mutex<dyn Guard + Send>>,
) -> Result<()> {
    let shutdown = Shutdown::new();
    let mut facade = Facade::new(shutdown.clone())?;

    facade
        .setup(Box::new(move |app_name| {
            let app_name = String::from(app_name);
            let cloned_controller = controller.clone();
            let cloned_configuration = configuration.clone();
            let cloned_queue_setup = queue_setup.clone();
            let cloned_guard = guard.clone();
            Box::pin(async move {
                cloned_controller
                    .lock()
                    .await
                    .register(
                        &app_name,
                        cloned_configuration,
                        cloned_queue_setup,
                        cloned_guard,
                    )
                    .await
            })
        }))
        .await?;

    println!("Started detnetctl");

    // Wait for shutdown
    match shutdown.wrap_cancel(signal::ctrl_c()).await {
        Some(Ok(())) => {}
        Some(Err(err)) => {
            eprintln!("listening to shutdown signal failed: {}", err);
            // we also shut down in case of error
        }
        None => {}
    }

    shutdown.shutdown();
    shutdown.wait_shutdown_complete().await;

    Ok(())
}

#[cfg(not(feature = "dbus"))]
async fn spawn_dbus_service(
    _controller: Arc<Mutex<Controller>>,
    mut _configuration: Box<dyn Configuration + Send>,
    mut _queue_setup: Box<dyn QueueSetup + Send>,
    mut _guard: Box<dyn Guard + Send>,
) -> Result<()> {
    Err(feature_missing_error("dbus", "--app-name"))
}

#[cfg(feature = "bpf")]
use detnetctl::guard::BPFGuard;
#[cfg(feature = "bpf")]
fn new_bpf_guard(debug_output: bool) -> Result<Arc<Mutex<dyn Guard + Send>>> {
    Ok(Arc::new(Mutex::new(BPFGuard::new(debug_output))))
}

#[cfg(not(feature = "bpf"))]
fn new_bpf_guard(_debug_output: bool) -> Result<Arc<Mutex<dyn Guard + Send>>> {
    Err(feature_missing_error("bpf", "--no-guard"))
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
    Ok(Arc::new(Mutex::new(DetdGateway::new(None, None)?)))
}

#[cfg(not(feature = "detd"))]
fn new_detd_gateway() -> Result<Arc<Mutex<dyn QueueSetup + Send>>> {
    Err(feature_missing_error("detd", "--no-queue-setup"))
}
