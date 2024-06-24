// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::facade::{ProtectCallback, PtpStatusCallback};
use anyhow::{anyhow, Context, Result};
use async_shutdown::Shutdown;
use async_trait::async_trait;
use chrono::Duration;
use dbus::channel::MatchingReceiver;
use dbus::nonblock::stdintf::org_freedesktop_dbus::RequestNameReply;
use dbus_crossroads::{Crossroads, IfaceToken};
use num_traits::ToPrimitive;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

#[cfg(not(test))]
use {
    dbus::nonblock::{Proxy, SyncConnection},
    dbus_tokio::connection,
};

#[cfg(test)]
mod mocks;
#[cfg(test)]
use {mocks::MockSyncConnection as SyncConnection, mocks::Mockconnection as connection};

const DBUS_NAME: &str = "org.detnet.detnetctl1";
const OBJECT_NAME: &str = "/org/detnet/detnetctl1";
const DBUS_APP_PREFIX: &str = "org.detnet.apps1.";

type DbusPtpStatus = (u8, i64, i64, i32, u8, i64);

#[derive(Debug)]
enum Command {
    Protect {
        sender: String,
        app_name: String,
        cgroup: String,
        responder: oneshot::Sender<Result<()>>,
    },
    GetPtpStatus {
        interface: String,
        max_clock_delta_ns: u64,
        max_master_offset_ns: u64,
        responder: oneshot::Sender<Result<DbusPtpStatus>>,
    },
}

pub(crate) struct DBus {
    c: Arc<SyncConnection>,
    resource_handle: Arc<tokio::task::JoinHandle<()>>,
    shutdown: Shutdown,
}

impl DBus {
    pub(crate) fn new(shutdown: Shutdown) -> Result<Self> {
        // Connect to system D-Bus
        let (resource, c) = connection::new_system_sync()?;

        // Spawn resource handler (and shut down if it exits)
        let resource_handle = tokio::spawn({
            shutdown.wrap_vital(async {
                let err = resource.await;
                eprintln!("Lost connection to D-Bus: {err}");
            })
        });

        Ok(Self {
            c,
            resource_handle: Arc::new(resource_handle),
            shutdown,
        })
    }

    pub(crate) async fn setup(
        &self,
        protect: ProtectCallback,
        get_ptp_status: Option<PtpStatusCallback>,
    ) -> Result<()> {
        // Request D-Bus name
        let reply = self.c.request_name(DBUS_NAME, false, true, true).await?;
        if reply != RequestNameReply::PrimaryOwner {
            return Err(anyhow!(
                "Can not request D-Bus name. Is detnetctl already running?"
            ));
        }

        // Communication channel between D-Bus message handler and registration manager
        let (tx, rx) = mpsc::channel::<Command>(32);

        // Spawn registration manager
        let manager_connection = self.c.clone();
        let resource_handle = self.resource_handle.clone();
        let manager_shutdown = self.shutdown.clone();
        let has_ptp_status_callback = get_ptp_status.is_some();
        tokio::spawn(async move {
            command_processor(
                rx,
                protect,
                get_ptp_status,
                manager_shutdown,
                manager_connection,
                resource_handle,
            )
            .await;
        });

        // Setup D-Bus message handler
        let mut cr = Crossroads::new();
        let cr_shutdown = self.shutdown.clone();
        cr.set_async_support(Some((
            self.c.clone(),
            Box::new(move |x| {
                cr_shutdown.wrap_wait(x).map_or_else(
                    |_| {
                        eprintln!("Shutdown happened, D-Bus operation aborted");
                    },
                    |future| {
                        tokio::spawn(future);
                    },
                );
            }),
        )));

        let token = protect_methods(&mut cr, tx, has_ptp_status_callback);
        cr.insert(OBJECT_NAME, &[token], ());

        // Interconnect connection with crossroads to handle message
        self.c.start_receive(
            dbus::message::MatchRule::new_method_call(),
            Box::new(move |msg, conn| {
                if cr.handle_message(msg, conn).is_err() {
                    eprintln!("Invalid message can not be processed");
                }
                true
            }),
        );

        Ok(())
    }
}

fn protect_methods(
    cr: &mut Crossroads,
    tx: mpsc::Sender<Command>,
    ptp_status: bool,
) -> IfaceToken<()> {
    let tx_for_protect = tx.clone();
    let tx_for_ptp_status = tx;

    cr.register(DBUS_NAME, |b| {
        b.method_with_cr_async(
            "Protect",
            ("app_name", "cgroup"),
            (),
            move |mut context, _, (app_name,cgroup): (String,String)| {
                let tx_clone = tx_for_protect.clone();

                async move {
                    let Some(sender) = context.message().sender() else {
                            return context.reply(Err(dbus::MethodErr::failed(&anyhow!(
                                "Can not determine D-Bus sender"
                            ))));
                        };

                    let (resp_tx, resp_rx) = oneshot::channel();

                    let cmd = Command::Protect {
                        app_name,
                        cgroup,
                        sender: String::from(&*sender),
                        responder: resp_tx,
                    };

                    if let Err(e) = tx_clone.send(cmd).await {
                        return context.reply(Err(dbus::MethodErr::failed(&e)));
                    }

                    let response = resp_rx.await;
                    context.reply(match response {
                        Ok(r) => match r {
                            Ok(_r) => Ok(()),
                            Err(e) => Err(dbus::MethodErr::failed(&e)),
                        },
                        Err(e) => Err(dbus::MethodErr::failed(&e)),
                    })
                }
            },
        );

        if ptp_status {
            b.method_with_cr_async(
                "PtpStatus",
                ("interface","max_clock_delta_ns","max_master_offset_ns"),
                (
                    "issues",
                    "phc_rt_delta",
                    "phc_tai_delta",
                    "kernel_tai_offset",
                    "port_state",
                    "master_offset",
                ),
                move |mut context, _, (interface,max_clock_delta_ns,max_master_offset_ns): (String,u64,u64)| {
                    let tx_clone = tx_for_ptp_status.clone();

                    async move {
                        let (resp_tx, resp_rx) = oneshot::channel();

                        let cmd = Command::GetPtpStatus {
                            interface,
                            max_clock_delta_ns,
                            max_master_offset_ns,
                            responder: resp_tx,
                        };

                        if let Err(e) = tx_clone.send(cmd).await {
                            return context.reply(Err(dbus::MethodErr::failed(&e)));
                        }

                        context.reply(match resp_rx.await {
                            Ok(r) => match r {
                                Ok(status) => Ok(status),
                                Err(e) => Err(dbus::MethodErr::failed(&e)),
                            },
                            Err(e) => Err(dbus::MethodErr::failed(&e)),
                        })
                    }
                },
            );
        }
    })
}

async fn command_processor(
    mut command_rx: mpsc::Receiver<Command>,
    mut protect: ProtectCallback,
    mut get_ptp_status: Option<PtpStatusCallback>,
    shutdown: Shutdown,
    connection: Arc<SyncConnection>,
    resource_handle: Arc<tokio::task::JoinHandle<()>>,
) {
    // delay token to delay shutdown until thread is finished
    let Ok(_delay_token) = shutdown.delay_shutdown_token() else {
        resource_handle.abort();
        return;
    };

    while let Some(Some(cmd)) = shutdown.wrap_cancel(command_rx.recv()).await {
        match cmd {
            Command::Protect {
                app_name,
                cgroup,
                sender,
                responder,
            } => {
                // It is important to verify the app name for making sure that
                // the sender is actually allowed to protect this app!
                let response = match verify_app_name(&app_name, &sender, connection.clone()).await {
                    Ok(()) => protect(&app_name, &cgroup).await.map_err(|e| {
                        // print here and forward, otherwise the error would only be sent back to the application
                        eprintln!("{e:#}");
                        e
                    }),
                    Err(e) => Err(e),
                };

                // Send back the response
                drop(responder.send(response));
            }

            Command::GetPtpStatus {
                interface,
                max_clock_delta_ns,
                max_master_offset_ns,
                responder,
            } => {
                if let Some(ptp_status_callback) = &mut get_ptp_status {
                    let response = ptp_status_callback(
                        &interface,
                        Duration::nanoseconds(max_clock_delta_ns.try_into().unwrap_or(i64::MAX)),
                        Duration::nanoseconds(max_master_offset_ns.try_into().unwrap_or(i64::MAX)),
                    )
                    .await;
                    drop(responder.send(response.and_then(|status| {
                        Ok((
                            status.issues.bits(),
                            status
                                .times
                                .phc_rt
                                .num_nanoseconds()
                                .ok_or_else(|| anyhow!("PHC RT out of range"))?,
                            status
                                .times
                                .phc_tai
                                .num_nanoseconds()
                                .ok_or_else(|| anyhow!("PHC TAI out of range"))?,
                            status
                                .kernel_tai_offset
                                .num_seconds()
                                .try_into()
                                .context("Converting kernel TAI offset")?,
                            status
                                .port_state
                                .to_u8()
                                .ok_or_else(|| anyhow!("Invalid port state"))?,
                            status
                                .master_offset
                                .num_nanoseconds()
                                .ok_or_else(|| anyhow!("Master offset out of range"))?,
                        ))
                    })));
                } else {
                    drop(responder.send(Err(anyhow!("No PTP status callback protected"))));
                }
            }
        }
    }

    shutdown.shutdown(); // make sure the program shuts down if the channel was closed due to an error, no-op for normal shutdown
    resource_handle.abort(); // stop dbus_tokio resource handler
}

async fn verify_app_name(
    app_name: &str,
    sender: &str,
    connection: Arc<SyncConnection>,
) -> Result<()> {
    let mut full_name = String::from(DBUS_APP_PREFIX);
    full_name.push_str(app_name);

    let owner = connection.get_owner(&full_name).await?;

    if sender == owner {
        Ok(())
    } else {
        Err(anyhow!(
            "Owner of D-Bus name does not match sender of registration message for {}",
            app_name
        ))
    }
}

#[async_trait]
trait GetOwner {
    async fn get_owner(&self, full_name: &str) -> Result<String>;
}

#[async_trait]
#[cfg(not(test))]
impl GetOwner for SyncConnection {
    async fn get_owner(&self, full_name: &str) -> Result<String> {
        use std::time::Duration;

        let proxy = Proxy::new(
            "org.freedesktop.DBus",
            "/",
            Duration::from_millis(5000),
            self,
        );
        let (owner,): (String,) = proxy
            .method_call("org.freedesktop.DBus", "GetNameOwner", (full_name,))
            .await?;
        Ok(owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ptp;
    use chrono::{Duration, NaiveDateTime};
    use dbus::channel::Token;
    use dbus::strings::BusName;
    use dbus::Message;
    use mockall::predicate;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    const APP_NAME: &str = "testapp";
    const CGROUP: &str = "testcgroup";
    const SENDER: &str = ":1.5";

    type CatchedResponse = Arc<Mutex<Option<Message>>>;

    struct DBusTester {
        msg: Message,
        protect_called: bool,
    }

    impl DBusTester {
        async fn perform_test(
            sent_app_name: String,
            sent_cgroup: String,
            dbus_names: HashMap<String, String>,
        ) -> Result<Self> {
            let shutdown = Shutdown::new();
            let rh_shutdown = shutdown.clone();
            let resource_handle =
                tokio::spawn(async move { rh_shutdown.wait_shutdown_triggered().await });

            let mut c = SyncConnection::default();
            c.expect_request_name()
                .times(1)
                .returning(|_, _, _, _| Ok(RequestNameReply::PrimaryOwner));

            let catched_response: CatchedResponse = Arc::new(Mutex::new(None));
            let catched_response_for_send = catched_response.clone();
            c.expect_send().returning(move |msg| {
                *catched_response_for_send.lock().unwrap() = Some(msg);
                Ok(0)
            });

            let mut full_sent_name = String::from(DBUS_APP_PREFIX);
            full_sent_name.push_str(&sent_app_name);
            c.expect_get_owner()
                .with(predicate::eq(full_sent_name)) // make sure get_owner is called with correct name
                .times(1)
                .returning(move |app_name| {
                    dbus_names
                        .get(app_name)
                        .ok_or_else(|| anyhow!("app_name not in dbus_names"))
                        .map(Clone::clone)
                });

            c.expect_start_receive()
                .returning(move |_, mut receive_callback| {
                    let mut message =
                        Message::new_method_call(DBUS_NAME, OBJECT_NAME, DBUS_NAME, "Protect")
                            .expect("method can not be created")
                            .append2(&sent_app_name, &sent_cgroup);
                    message.set_sender(Some(BusName::from(SENDER)));
                    message.set_serial(123);

                    receive_callback(message, &SyncConnection::default());
                    Token(5)
                });

            let dbus = DBus {
                c: Arc::new(c),
                resource_handle: Arc::new(resource_handle),
                shutdown: shutdown.clone(),
            };

            let protect_called = Arc::new(AtomicBool::new(false));
            let protect_called_for_setup = protect_called.clone();
            dbus.setup(
                Box::new(move |_, _| {
                    protect_called_for_setup.store(true, Ordering::Relaxed);
                    Box::pin(async move { Ok(()) })
                }),
                Some(Box::new(move |_, _, _| {
                    Box::pin(async move {
                        Ok(ptp::PtpStatus {
                            times: ptp::PtpTimes {
                                rt: NaiveDateTime::from_timestamp_millis(0)
                                    .ok_or_else(|| anyhow!("fail"))?,
                                tai: NaiveDateTime::from_timestamp_millis(0)
                                    .ok_or_else(|| anyhow!("fail"))?,
                                ptp: NaiveDateTime::from_timestamp_millis(0)
                                    .ok_or_else(|| anyhow!("fail"))?,
                                lat_rt: Duration::seconds(0),
                                lat_tai: Duration::seconds(0),
                                lat_ptp: Duration::seconds(0),
                                phc_rt: Duration::seconds(0),
                                phc_tai: Duration::seconds(0),
                            },
                            issues: None.into(),
                            port_state: ptp::PortStates::Faulty,
                            master_offset: Duration::seconds(0),
                            kernel_tai_offset: Duration::seconds(0),
                        })
                    })
                })),
            )
            .await?;

            dbus.shutdown.wait_shutdown_complete().await;

            let response = catched_response
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .duplicate()
                .map_err(|s| anyhow!(s))?;

            Ok(Self {
                msg: response,
                protect_called: protect_called.load(Ordering::Relaxed),
            })
        }
    }

    #[tokio::test]
    async fn test_happy() -> Result<()> {
        let mut dbus_names = HashMap::new();
        dbus_names.insert(DBUS_APP_PREFIX.to_owned() + APP_NAME, String::from(SENDER));
        let result =
            DBusTester::perform_test(APP_NAME.to_owned(), CGROUP.to_owned(), dbus_names).await?;

        assert!(result.protect_called);

        Ok(())
    }

    #[tokio::test]
    #[should_panic(
        expected = "Owner of D-Bus name does not match sender of registration message for testapp"
    )]
    async fn test_owner_not_matching() {
        let mut dbus_names = HashMap::new();
        dbus_names.insert(
            DBUS_APP_PREFIX.to_owned() + APP_NAME,
            String::from(":1:123"),
        );
        let mut result =
            DBusTester::perform_test(APP_NAME.to_owned(), CGROUP.to_owned(), dbus_names)
                .await
                .unwrap();

        assert!(!result.protect_called);
        result.msg.as_result().unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "D-Bus error: app_name not in dbus_names")]
    async fn test_name_not_found() {
        let mut dbus_names = HashMap::new();
        dbus_names.insert(
            DBUS_APP_PREFIX.to_owned() + "otherapp",
            String::from(SENDER),
        );
        let mut result =
            DBusTester::perform_test(APP_NAME.to_owned(), CGROUP.to_owned(), dbus_names)
                .await
                .unwrap();

        assert!(!result.protect_called);
        result.msg.as_result().unwrap();
    }
}
