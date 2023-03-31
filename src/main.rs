extern crate detnetctl;

use anyhow::{bail, Result};
use clap::Parser;
use std::fs::File;
use std::path::PathBuf;

use detnetctl::configuration::YAMLConfiguration;
use detnetctl::controller::{Controller, Registration};
use detnetctl::guard::DummyGuard;
use detnetctl::nic_setup::DummyNICSetup;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Oneshot registration with the provided app name
    #[arg(short, long)]
    app_name: Option<String>,

    /// Use YAML configuration with the provided file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Skip NIC setup and return the given PRIORITY
    #[arg(long, value_name = "PRIORITY")]
    no_nic_setup: Option<u8>,

    /// Skip installing eBPFs - no interference protection!
    #[arg(long)]
    no_guard: bool,
}

#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut configuration = match cli.config {
        Some(file) => {
            let mut c = Box::new(YAMLConfiguration::new());
            c.read(File::open(file)?)?;
            c
        }
        None => {
            bail!("Not yet implemented, please provide --config");
        }
    };

    let mut nic_setup = match cli.no_nic_setup {
        Some(priority) => Box::new(DummyNICSetup::new(priority)),
        None => {
            bail!("Not yet implemented, please provide --no-nic-setup");
        }
    };

    let mut guard = match cli.no_guard {
        true => Box::new(DummyGuard::new()),
        false => {
            bail!("Not yet implemented, please provide --no-guard");
        }
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
        None => {
            bail!("Not yet implemented, please provide --app-name");
        }
    }

    Ok(())
}
