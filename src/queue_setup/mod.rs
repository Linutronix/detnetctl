// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Setup a TSN-capable NIC and qdiscs
#![cfg_attr(not(feature = "netlink"), doc = "```ignore")]
#![cfg_attr(feature = "netlink", doc = "```no_run")]
//! use detnetctl::queue_setup::{QueueSetup, TaprioSetup};
//! use std::collections::BTreeMap;
//! use std::net::{IpAddr, Ipv4Addr};
//! use detnetctl::configuration::{InterfaceBuilder, GateControlEntryBuilder, ScheduleBuilder,
//!                                GateOperation, QueueMapping, TaprioConfigBuilder, Mode};
//!
//! # tokio_test::block_on(async {
//! let interface_config = InterfaceBuilder::new()
//!    .schedule(
//!        ScheduleBuilder::new()
//!            .basetime_ns(10)
//!            .control_list(vec![GateControlEntryBuilder::new()
//!                .operation(GateOperation::SetGates)
//!                .time_interval_ns(1000)
//!                .traffic_classes(vec![1, 2])
//!                .build()])
//!            .number_of_traffic_classes(3)
//!            .priority_map(BTreeMap::from([(0, 1)]))
//!            .build(),
//!    )
//!    .taprio(
//!        TaprioConfigBuilder::new()
//!            .mode(Mode::FullOffload)
//!            .queues(vec![
//!                QueueMapping {
//!                    count: 2,
//!                    offset: 0,
//!                },
//!                QueueMapping {
//!                    count: 1,
//!                    offset: 2,
//!                },
//!                QueueMapping {
//!                    count: 1,
//!                    offset: 3,
//!                },
//!            ])
//!            .build(),
//!    )
//!    .addresses(vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 3)), 16)])
//!    .build();
//!
//! let mut queue_setup = TaprioSetup;
//! let response = queue_setup.apply_config("eth0", &interface_config).await?;
//! # Ok::<(), anyhow::Error>(())
//! # });
//! # Ok::<(), anyhow::Error>(())
//! ```

use crate::configuration::Interface;
use anyhow::Result;
use async_trait::async_trait;

#[cfg(test)]
use mockall::automock;

#[cfg(feature = "netlink")]
mod taprio;
#[cfg(feature = "netlink")]
pub use taprio::TaprioSetup;

/// Defines how to apply an Ethernet configuration
#[cfg_attr(test, automock)]
#[async_trait]
pub trait QueueSetup {
    /// Apply the given configuration by setting up NIC and qdiscs
    ///
    /// # Errors
    ///
    /// Will return `Err` if the configuration could not be applied,
    /// e.g. because the configuration itself is invalid or the system
    /// is in a state that does not allow applying this configuration.
    async fn apply_config(&self, interface_name: &str, interface_config: &Interface) -> Result<()>;
}

/// A queue setup doing nothing, but still providing the `QueueSetup` trait
///
/// Useful for testing purposes (e.g. with NICs without TSN capabilities)
/// or if you only want to use other features without actually configuring the NIC.
pub struct DummyQueueSetup;

#[async_trait]
impl QueueSetup for DummyQueueSetup {
    async fn apply_config(
        &self,
        _interface_name: &str,
        _interface_config: &Interface,
    ) -> Result<()> {
        Ok(())
    }
}
