// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Error, Result};
use detnetctl::configuration::{Schedule, ScheduleConfiguration, SysrepoScheduleConfiguration};
use detnetctl::queue_setup::TaprioSetup;

/// Main function of the qcw2taprio tool
#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<()> {
    let interface_name = "enp86s0";

    let mut config = SysrepoScheduleConfiguration::new()?;
    let schedule = config.get_schedule(interface_name)?;
    println!("{schedule:#?}");

    let taprio = TaprioSetup::setup(interface_name, &schedule).await;

    Ok(())
}
