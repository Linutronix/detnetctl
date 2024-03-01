// SPDX-FileCopyrightText: 2023 Linutronix GmbH
// SPDX-License-Identifier: GPL-3.0-or-later

//! Helper for starting a program in a separate cgroup
//! and passing that to detnetctl.

use anyhow::{anyhow, Error, Result};
use clap::Parser;
use dbus::arg;
use dbus::arg::{RefArg, Variant};
use dbus::blocking::stdintf::org_freedesktop_dbus::RequestNameReply;
use dbus::blocking::{Connection, Proxy};
use dbus::Message;
use regex::Regex;
use std::fs;
use std::io;
use std::io::BufRead;
use std::path::Path;
use std::process;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;
use tokio::process::Command;
use tokio::time::sleep;

const CGROUP_PREFIX: &str = "detnetctl";
const UNIT_EXISTS_ERROR: Option<&str> = Some("org.freedesktop.systemd1.UnitExists");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, trailing_var_arg=true)]
struct Cli {
    /// Register with the provided app_name
    app_name: String,

    /// Command to start as child process
    command: String,

    /// Arguments to pass to the child process
    #[clap(allow_hyphen_values = true)]
    arguments: Vec<String>,
}

/// Main function of the detnetctl-run tool
///
/// # Errors
/// Will return `Err` if any error occurs that can not be handled
/// such as problems in the D-Bus communication with systemd or
/// detnetctl.
///
/// # Panics
/// If the called program panics (i.e. a return code != 0)
#[tokio::main(flavor = "current_thread")]
#[allow(clippy::redundant_pub_crate)] // for tokio::select! (https://github.com/rust-lang/rust-clippy/issues/10636)
pub async fn main() -> Result<()> {
    let cli = Cli::parse();

    move_to_individual_child_cgroup(process::id(), &cli.app_name)?;

    sleep(Duration::from_secs(2)).await;
    let cgroup = get_cgroup(process::id())?;

    register_detnet_app(&cli.app_name, &cgroup)?;

    let mut child = Command::new(cli.command).args(cli.arguments).spawn()?;

    // by capturing SIGINT we avoid that detnetctl-run
    // exits too early before the child process exits
    let exit_status = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            child.wait().await?
        },
        r = child.wait() => {
            r?
        }
    };

    std::process::exit(exit_status.code().unwrap_or(1));
}

#[derive(Debug)]
struct OrgFreedesktopSystemd1ManagerJobRemoved {
    id: u32,
    job: dbus::Path<'static>,
    unit: String,
    result: String,
}

impl arg::AppendAll for OrgFreedesktopSystemd1ManagerJobRemoved {
    fn append(&self, i: &mut arg::IterAppend<'_>) {
        arg::RefArg::append(&self.id, i);
        arg::RefArg::append(&self.job, i);
        arg::RefArg::append(&self.unit, i);
        arg::RefArg::append(&self.result, i);
    }
}

impl arg::ReadAll for OrgFreedesktopSystemd1ManagerJobRemoved {
    fn read(i: &mut arg::Iter<'_>) -> Result<Self, arg::TypeMismatchError> {
        Ok(Self {
            id: i.read()?,
            job: i.read()?,
            unit: i.read()?,
            result: i.read()?,
        })
    }
}

impl dbus::message::SignalArgs for OrgFreedesktopSystemd1ManagerJobRemoved {
    const NAME: &'static str = "JobRemoved";
    const INTERFACE: &'static str = "org.freedesktop.systemd1.Manager";
}

fn start_transient_unit(
    proxy: &Proxy<'_, &Connection>,
    unit_name: &str,
    pid: u32,
) -> Result<String, dbus::Error> {
    type AuxValue = Vec<(String, Variant<Box<dyn RefArg>>)>;
    let mode = "fail";
    let properties = vec![("PIDs", Variant(vec![pid]))];
    let aux: Vec<(String, AuxValue)> = vec![];

    proxy
        .method_call(
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
            (unit_name, mode, properties, aux),
        )
        .map(|(o,): (dbus::Path<'_>,)| Ok(o.to_string()))?
}

fn move_to_individual_child_cgroup(pid: u32, app_name: &str) -> Result<()> {
    let conn = Connection::new_session()?;

    let proxy = conn.with_proxy(
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        Duration::from_millis(5000),
    );

    let (tx, rx) = mpsc::channel();

    let _id = proxy.match_signal(
        move |h: OrgFreedesktopSystemd1ManagerJobRemoved, _: &Connection, _: &Message| {
            drop(tx.send(h.job.to_string()));
            true
        },
    );

    let unit_name = format!("{CGROUP_PREFIX}.{app_name}.scope");
    let object = start_transient_unit(&proxy, &unit_name, pid)
        .or_else(|e| {
            if e.name() == UNIT_EXISTS_ERROR {
                // If the previous invocation failed, the scope still exists,
                // so try to reset the failed state, then retry
                reset_failed(&proxy, &unit_name)?;
                start_transient_unit(&proxy, &unit_name, pid)
            } else {
                Err(e)
            }
        })
        .map_err(|e| {
            if e.name() == UNIT_EXISTS_ERROR {
                anyhow!("An application is already running in scope {unit_name}")
            } else {
                Error::new(e)
            }
        })?;

    let timeout = Duration::from_secs(5);
    let end_time = Instant::now() + timeout;
    while Instant::now() < end_time {
        proxy.connection.process(timeout)?;
        match rx.try_recv() {
            Ok(p) => {
                if p == object {
                    // systemd job is finished, cgroup is prepared
                    return Ok(());
                }
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(anyhow!("DBus signal match ended before systemd job ended"))
            }
        }
    }

    Err(anyhow!(
        "Timeout while waiting for systemd start job to finish"
    ))
}

fn reset_failed(proxy: &Proxy<'_, &Connection>, unit_name: &str) -> Result<(), dbus::Error> {
    proxy.method_call(
        "org.freedesktop.systemd1.Manager",
        "ResetFailedUnit",
        (unit_name,),
    )
}

fn get_cgroup(pid: u32) -> Result<String> {
    let lines = read_lines(format!("/proc/{pid}/cgroup"))?;
    let re = Regex::new(r"0::([^ ]*)")?;
    for line in lines.map_while(Result::ok) {
        if let Some(caps) = re.captures(&line) {
            if let Some(m) = caps.get(1) {
                return Ok(m.as_str().to_owned());
            }
        }
    }

    Err(anyhow!("cgroup not found"))
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<fs::File>>>
where
    P: AsRef<Path>,
{
    let file = fs::File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn register_detnet_app(app_name: &str, cgroup: &str) -> Result<()> {
    let conn = Connection::new_system()?;

    let proxy = conn.with_proxy(
        "org.detnet.detnetctl1",
        "/org/detnet/detnetctl1",
        Duration::from_millis(10000),
    );

    // Request name to authenticate against detnetctl
    let name = format!("org.detnet.apps1.{app_name}");
    let request_reply = conn.request_name(name, true, true, true)?;
    if request_reply != RequestNameReply::PrimaryOwner {
        return Err(anyhow!("Not the primary owner of the D-Bus name! Is the process run under the correct user according to the D-Bus policy?"));
    }

    // Protect the DetNet app
    proxy.method_call("org.detnet.detnetctl1", "Protect", (app_name, cgroup))?;

    Ok(())
}
