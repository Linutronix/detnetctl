// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use clap::{error::ErrorKind, CommandFactory, Parser};
use detnetctl::configuration::{Schedule, ScheduleConfiguration, SysrepoScheduleConfiguration};
use detnetctl::queue_setup::{ClockId, Mode, TaprioSetup};
use env_logger::Env;

#[derive(Parser, Debug)]
#[command(author, version, about = "Sets up TAPRIO qdiscs from current sysrepo state", long_about = None, trailing_var_arg=true)]
struct Cli {
    /// Offload mode.
    #[arg(short, long, default_value_t = Mode::FullOffload)]
    mode: Mode,

    /// Interface (if not provided, use all that have a schedule in the sysrepo)
    #[clap(short, long)]
    interface: Option<String>,

    /// Set Clock ID. Not allowed for FULL_OFFLOAD mode, mandatory for the other modes.
    #[clap(
        short,
        long,
        required_if_eq("mode", "SOFTWARE"),
        required_if_eq("mode", "TX_TIME_ASSIST")
    )]
    clock_id: Option<ClockId>,

    /// TX time delay for TX_TIME_ASSIST mode
    #[clap(short = 'd', long, required_if_eq("mode", "TX_TIME_ASSIST"))]
    txtime_delay: Option<u32>,

    /// For priorities not provided in the priority to tc map, use this tc
    #[arg(short, long, default_value_t = 0)]
    tc_fallback: u8,

    /// Maps traffic classes to queues
    /// Format: count1@offset1 count2@offset2 ...
    /// The default performs a one-to-one mapping of traffic classes and queues (1@0 1@1 ... 1@<num_tc-1>)
    #[arg(verbatim_doc_comment)]
    queues: Vec<String>,
}

/// Main function of the qcw2taprio tool
#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("warn")).init();

    let cli = Cli::parse();

    if cli.mode == Mode::FullOffload && cli.clock_id.is_some() {
        Cli::command()
            .error(
                ErrorKind::ArgumentConflict,
                "Specifying Clock ID not allowed for full offload mode!",
            )
            .exit();
    }

    if cli.mode != Mode::TxTimeAssist && cli.txtime_delay.is_some() {
        Cli::command()
            .error(
                ErrorKind::ArgumentConflict,
                "TX time delay has no meaning unless TX_TIME_ASSIST is used!",
            )
            .exit();
    }

    let taprio = TaprioSetup {
        mode: cli.mode,
        clock_id: cli.clock_id,
        txtime_delay: cli.txtime_delay,
        tc_fallback: cli.tc_fallback,
        queues: cli.queues,
    };

    let mut config = SysrepoScheduleConfiguration::new()?;

    if let Some(interface) = cli.interface {
        let schedule = config.get_schedule(&interface)?;
        setup_taprio_qdisc(&taprio, &interface, &schedule).await?;
    } else {
        let schedules = config.get_schedules()?;
        for (interface, schedule) in &schedules {
            setup_taprio_qdisc(&taprio, interface, schedule).await?;
            println!();
        }
    }

    Ok(())
}

async fn setup_taprio_qdisc(
    taprio: &TaprioSetup,
    interface: &str,
    schedule: &Schedule,
) -> Result<()> {
    println!("Setting up schedule for {interface}:");
    println!("{schedule:#?}");

    // Print tc command
    // Only for convenience, the actual setup directly uses netlink
    println!("Matching tc command:");
    let command = taprio.assemble_tc_command(interface, schedule)?;
    println!("{}\n", format!("{:?}", command).replace('\"', ""));

    // Setup qdisc via netlink
    taprio.setup(interface, schedule).await?;

    Ok(())
}
