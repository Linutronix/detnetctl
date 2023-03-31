extern crate detnetctl;

use anyhow::{anyhow, Error, Result};
use clap::Parser;
use std::fs::File;
use std::path::PathBuf;

use detnetctl::configuration::{Configuration, YAMLConfiguration};
use detnetctl::controller::{Controller, Registration};
use detnetctl::guard::{DummyGuard, Guard};
use detnetctl::nic_setup::{DummyNICSetup, NICSetup};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Oneshot registration with the provided app name and do not spawn D-Bus service
    #[arg(short, long)]
    app_name: Option<String>,

    /// Use YAML configuration with the provided file. Otherwise, uses sysrepo.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Skip NIC setup and return the given PRIORITY
    #[arg(long, value_name = "PRIORITY")]
    no_nic_setup: Option<u8>,

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

    let mut configuration = match cli.config {
        Some(file) => {
            let mut c = Box::new(YAMLConfiguration::new());
            c.read(File::open(file)?)?;
            c
        }
        None => new_sysrepo_config()?,
    };

    let mut nic_setup = match cli.no_nic_setup {
        Some(priority) => Box::new(DummyNICSetup::new(priority)),
        None => new_detd_gateway()?,
    };

    let mut guard = match cli.no_guard {
        true => Box::new(DummyGuard::new()),
        false => new_bpf_guard(cli.bpf_debug_output)?,
    };

    let controller = Controller::new();

    match cli.app_name {
        Some(app_name) => {
            let response = controller.register(
                &app_name,
                &mut *configuration,
                &mut *nic_setup,
                &mut *guard,
            )?;
            println!("Final result: {:#?}", response);
        }
        None => spawn_dbus_service(controller, configuration, nic_setup, guard).await?,
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
    controller: Controller,
    mut configuration: Box<dyn Configuration + Send>,
    mut nic_setup: Box<dyn NICSetup + Send>,
    mut guard: Box<dyn Guard + Send>,
) -> Result<()> {
    let shutdown = Shutdown::new();
    let mut facade = Facade::new(shutdown.clone())?;

    facade
        .setup(Box::new(move |app_name| {
            controller.register(app_name, &mut *configuration, &mut *nic_setup, &mut *guard)
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
    _controller: Controller,
    mut _configuration: Box<dyn Configuration + Send>,
    mut _nic_setup: Box<dyn NICSetup + Send>,
    mut _guard: Box<dyn Guard + Send>,
) -> Result<()> {
    Err(feature_missing_error("dbus", "--app-name"))
}

#[cfg(feature = "bpf")]
use detnetctl::guard::BPFGuard;
#[cfg(feature = "bpf")]
fn new_bpf_guard(debug_output: bool) -> Result<Box<dyn Guard + Send>> {
    Ok(Box::new(BPFGuard::new(debug_output)))
}

#[cfg(not(feature = "bpf"))]
fn new_bpf_guard(_debug_output: bool) -> Result<Box<dyn Guard + Send>> {
    Err(feature_missing_error("bpf", "--no-guard"))
}

#[cfg(feature = "sysrepo")]
use detnetctl::configuration::SysrepoConfiguration;
#[cfg(feature = "sysrepo")]
fn new_sysrepo_config() -> Result<Box<dyn Configuration + Send>> {
    Ok(Box::new(SysrepoConfiguration::new()?))
}

#[cfg(not(feature = "sysrepo"))]
fn new_sysrepo_config() -> Result<Box<dyn Configuration + Send>> {
    Err(feature_missing_error("sysrepo", "--config"))
}

#[cfg(feature = "detd")]
use detnetctl::nic_setup::DetdGateway;
#[cfg(feature = "detd")]
fn new_detd_gateway() -> Result<Box<dyn NICSetup + Send>> {
    Ok(Box::new(DetdGateway::new(None, None)?))
}

#[cfg(not(feature = "detd"))]
fn new_detd_gateway() -> Result<Box<dyn NICSetup + Send>> {
    Err(feature_missing_error("detd", "--no-nic-setup"))
}
