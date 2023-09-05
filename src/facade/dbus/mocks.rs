// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::facade::dbus::GetOwner;
use anyhow::Result;
use async_trait::async_trait;
use dbus::channel::{Channel, MatchingReceiver, Sender, Token};
use dbus::message::MatchRule;
use dbus::nonblock::stdintf::org_freedesktop_dbus::RequestNameReply;
use dbus::nonblock::Process;
use dbus::{Error, Message};
use dbus_tokio::connection::IOResource;
use mockall::mock;
use std::sync::Arc;

mock! {
    pub SyncConnection {
        pub async fn request_name(
            &self,
            name: &str,
            allow_replacement: bool,
            replace_existing: bool,
            do_not_queue: bool
        ) -> Result<RequestNameReply,Error>;
    }

    impl Sender for SyncConnection {
        fn send(&self, msg: Message) -> Result<u32, ()>;
    }

    impl MatchingReceiver for SyncConnection {
        type F = Box<dyn FnMut(Message, &MockSyncConnection) -> bool + Send + 'static>;
        fn start_receive(&self, m: MatchRule<'static>, f: <MockSyncConnection as MatchingReceiver>::F) -> Token;
        fn stop_receive(&self, id: Token) -> Option<(MatchRule<'static>, <MockSyncConnection as MatchingReceiver>::F)>;
    }

    impl Process for SyncConnection {
        fn process_one(&self, msg: Message);
    }

    impl AsRef<Channel> for SyncConnection {
        fn as_ref(&self) -> &Channel;
    }

    #[async_trait]
    impl GetOwner for SyncConnection {
        async fn get_owner(&self, full_name: &str) -> Result<String>;
    }
}

mock! {
    pub connection {
        pub fn new_system_sync() -> Result<(IOResource<MockSyncConnection>, Arc<MockSyncConnection>), Error>;
    }
}
