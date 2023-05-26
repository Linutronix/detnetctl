use crate::facade::RegisterCallback;
use anyhow::{anyhow, Result};
use async_shutdown::Shutdown;
use async_trait::async_trait;
use dbus::channel::MatchingReceiver;
use dbus_crossroads::Crossroads;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

#[cfg(not(test))]
use {
    core::time::Duration,
    dbus::nonblock::{Proxy, SyncConnection},
    dbus_tokio::connection,
};

#[cfg(test)]
mod mocks;
#[cfg(test)]
use {mocks::MockSyncConnection as SyncConnection, mocks::Mockconnection as connection};

use crate::controller;

const DBUS_NAME: &str = "org.detnet.detnetctl";
const OBJECT_NAME: &str = "/org/detnet/detnetctl";
const DBUS_APP_PREFIX: &str = "org.detnet.apps.";

#[derive(Debug)]
struct RegisterCommand {
    app_name: String,
    sender: String,
    responder: oneshot::Sender<Result<controller::RegisterResponse>>,
}

pub struct DBus {
    c: Arc<SyncConnection>,
    resource_handle: Arc<tokio::task::JoinHandle<()>>,
    shutdown: Shutdown,
}

impl DBus {
    pub fn new(shutdown: Shutdown) -> Result<Self> {
        // Connect to system D-Bus
        let (resource, c) = connection::new_system_sync()?;

        // Spawn resource handler (and shut down if it exits)
        let resource_handle = tokio::spawn({
            shutdown.wrap_vital(async {
                let err = resource.await;
                eprintln!("Lost connection to D-Bus: {}", err);
            })
        });

        Ok(DBus {
            c,
            resource_handle: Arc::new(resource_handle),
            shutdown,
        })
    }

    pub async fn setup(&self, mut register: RegisterCallback) -> Result<()> {
        // Request D-Bus name
        self.c.request_name(DBUS_NAME, false, true, false).await?;

        // Communication channel between D-Bus message handler and registration manager
        let (tx, mut rx) = mpsc::channel::<RegisterCommand>(32);

        // Spawn registration manager
        let manager_connection = self.c.clone();
        let resource_handle = self.resource_handle.clone();
        let manager_shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            // delay token to delay shutdown until thread is finished
            let _delay_token = match manager_shutdown.delay_shutdown_token() {
                Ok(token) => token,
                Err(_) => {
                    resource_handle.abort();
                    return;
                }
            };

            while let Some(Some(cmd)) = manager_shutdown.wrap_cancel(rx.recv()).await {
                // It is important to verify the app name for making sure that
                // the sender is actually allowed to register this app!
                let response = match Self::verify_app_name(
                    &cmd.app_name,
                    &cmd.sender,
                    manager_connection.clone(),
                )
                .await
                {
                    Ok(()) => register(&cmd.app_name).await.map_err(|e| {
                        // print here and forward, otherwise the error would only be sent back to the application
                        eprintln!("{:#}", e);
                        e
                    }),
                    Err(e) => Err(e),
                };

                // Send back the response
                let _ = cmd.responder.send(response);
            }

            manager_shutdown.shutdown(); // make sure the program shuts down if the channel was closed due to an error, no-op for normal shutdown
            resource_handle.abort(); // stop dbus_tokio resource handler
        });

        // Setup D-Bus message handler
        let mut cr = Crossroads::new();
        let cr_shutdown = self.shutdown.clone();
        cr.set_async_support(Some((
            self.c.clone(),
            Box::new(move |x| match cr_shutdown.wrap_wait(x) {
                Ok(future) => {
                    tokio::spawn(future);
                }
                Err(_) => {
                    eprintln!("Shutdown happened, D-Bus operation aborted");
                }
            }),
        )));

        let token = cr.register(DBUS_NAME, |b| {
            b.method_with_cr_async(
                "Register",
                ("app_name",),
                ("interface", "priority", "token"),
                move |mut context, _, (app_name,): (String,)| {
                    let tx_clone = tx.clone();

                    async move {
                        let sender = match context.message().sender() {
                            Some(sender) => sender,
                            None => {
                                return context.reply(Err(dbus::MethodErr::failed(&anyhow!(
                                    "Can not determine D-Bus sender"
                                ))));
                            }
                        };

                        let (resp_tx, resp_rx) = oneshot::channel();

                        let cmd = RegisterCommand {
                            app_name,
                            sender: String::from(&*sender),
                            responder: resp_tx,
                        };

                        tx_clone.send(cmd).await.unwrap();

                        let response = resp_rx.await;
                        context.reply(match response {
                            Ok(r) => match r {
                                Ok(r) => Ok((r.logical_interface, r.priority, r.token)),
                                Err(e) => Err(dbus::MethodErr::failed(&e)),
                            },
                            Err(e) => Err(dbus::MethodErr::failed(&e)),
                        })
                    }
                },
            );
        });
        cr.insert(OBJECT_NAME, &[token], ());

        // Interconnect connection with crossroads to handle message
        self.c.start_receive(
            dbus::message::MatchRule::new_method_call(),
            Box::new(move |msg, conn| {
                cr.handle_message(msg, conn).unwrap();
                true
            }),
        );

        Ok(())
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
}

#[async_trait]
trait GetOwner {
    async fn get_owner(&self, full_name: &str) -> Result<String>;
}

#[async_trait]
#[cfg(not(test))]
impl GetOwner for SyncConnection {
    async fn get_owner(&self, full_name: &str) -> Result<String> {
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
    use dbus::channel::Token;
    use dbus::strings::BusName;
    use dbus::Message;
    use mockall::predicate;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    const APP_NAME: &str = "testapp";
    const SENDER: &str = ":1.5";
    const INTERFACE: &str = "eth0.5";
    const PRIORITY: u8 = 3;
    const TOKEN: u64 = 12345;

    type CatchedResponse = Arc<Mutex<Option<Message>>>;

    struct DBusTester {
        pub msg: Message,
        pub register_called: bool,
    }

    impl DBusTester {
        async fn perform_test(
            sent_app_name: String,
            dbus_names: HashMap<String, String>,
        ) -> Result<Self> {
            let shutdown = Shutdown::new();
            let rh_shutdown = shutdown.clone();
            let resource_handle =
                tokio::spawn(async move { rh_shutdown.wait_shutdown_triggered().await });

            let mut c = SyncConnection::default();
            c.expect_request_name()
                .times(1)
                .returning(|_, _, _, _| Ok(()));

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
                        .map(|x| x.clone())
                });

            c.expect_start_receive()
                .returning(move |_, mut receive_callback| {
                    let mut message = dbus::Message::new_method_call(
                        DBUS_NAME,
                        OBJECT_NAME,
                        DBUS_NAME,
                        "Register",
                    )
                    .expect("method can not be created")
                    .append1(&sent_app_name);
                    message.set_sender(Some(BusName::from(SENDER)));
                    message.set_serial(123);

                    let c = SyncConnection::default();
                    receive_callback(message, &c);
                    Token(5)
                });

            let dbus = DBus {
                c: Arc::new(c),
                resource_handle: Arc::new(resource_handle),
                shutdown: shutdown.clone(),
            };

            let register_called = Arc::new(AtomicBool::new(false));
            let register_called_for_setup = register_called.clone();
            dbus.setup(Box::new(move |_| {
                register_called_for_setup.store(true, Ordering::Relaxed);
                Box::pin(async move {
                    Ok(controller::RegisterResponse {
                        logical_interface: String::from(INTERFACE),
                        priority: PRIORITY,
                        token: TOKEN,
                    })
                })
            }))
            .await?;

            dbus.shutdown.wait_shutdown_complete().await;

            let response_guard = catched_response.lock().unwrap();
            let response = response_guard
                .as_ref()
                .unwrap()
                .duplicate()
                .map_err(|s| anyhow!(s))?;

            Ok(DBusTester {
                msg: response,
                register_called: register_called.load(Ordering::Relaxed),
            })
        }
    }

    #[tokio::test]
    async fn test_happy() -> Result<()> {
        let mut dbus_names = HashMap::new();
        dbus_names.insert(DBUS_APP_PREFIX.to_owned() + APP_NAME, String::from(SENDER));
        let result = DBusTester::perform_test(String::from(APP_NAME), dbus_names).await?;

        assert!(result.register_called);

        let (interface, priority, token): (Option<String>, Option<u8>, Option<u64>) =
            result.msg.get3();
        assert_eq!(interface, Some(String::from(INTERFACE)));
        assert_eq!(priority, Some(PRIORITY));
        assert_eq!(token, Some(TOKEN));

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
        let mut result = DBusTester::perform_test(String::from(APP_NAME), dbus_names)
            .await
            .unwrap();

        assert!(!result.register_called);
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
        let mut result = DBusTester::perform_test(String::from(APP_NAME), dbus_names)
            .await
            .unwrap();

        assert!(!result.register_called);
        result.msg.as_result().unwrap();
    }
}
