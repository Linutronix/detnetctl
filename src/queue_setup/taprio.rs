// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use std::process::Command;

use crate::configuration::Schedule;
use crate::interface_setup::NetlinkSetup;

/// Setup TAPRIO via netlink
pub struct TaprioSetup;

impl TaprioSetup {
    pub async fn setup(interface_name: &str, schedule: &Schedule) -> Result<()> {
        println!("hallo");
        let mut command = Command::new("tc");

        command
            .args(&[
                "qdisc", "replace", "dev", interface_name, "parent", "root", "taprio",
            ])
            .args(&["num_tc", &schedule.number_of_traffic_classes.to_string()])
            .arg("map");

        for prio in &schedule.priority_map {
            command.arg(&prio.to_string());
        }

        command.args(&["2"; 8]); // TODO!

        command.arg("queues");

        // TODO?
        for i in 0..schedule.number_of_traffic_classes {
            command.arg(format!("1@{i}"));
        }

        command.args(&["base-time", &schedule.basetime_ns.to_string()]);

        for entry in &schedule.control_list {
            // TODO S!
            command.args(&["sched-entry", "S", &entry.gate_states_value.to_string(), &entry.time_interval_value_ns.to_string()]);
        }

        command.args(&["flags", "0x1"])
            .args(&["txtime-delay", "500000"])
            .args(&["clockid", "CLOCK_TAI"]);

        // TODO
        command.args(&["fp","P","E","E"]);
        command.args(&["P"; 13]);
        command.args(&["max-sdu","0","300","200"]);
        command.args(&["0"; 13]);
        command.args(&["cycle-time", &schedule.control_list.iter().map(|entry| entry.time_interval_value_ns).fold(0, |acc, val| acc + val).to_string()]); // sum is actually calculated automatically if not provided
        command.args(&["cycle-time-extension", "100"]);

        /*.output()
            .expect("Failed to execute command");

        // Display the command output
        println!("Command executed with status: {:?}", output.status);
        println!("Command output: {}", String::from_utf8_lossy(&output.stdout));
        println!("Command errors: {}", String::from_utf8_lossy(&output.stderr));*/

        //let cmd = command.program + " " + command.args.join(" ");
        println!("{}", format!("{:?}", command).replace("\"", ""));

        /*
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        let idx = NetlinkSetup::get_interface_index(interface_name, &handle).await?;

        handle
            .qdisc()
            .replace(0)
            .root()
            .execute()
            .await?;
            */

        Ok(())
    }
}
