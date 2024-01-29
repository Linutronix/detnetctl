// SPDX-FileCopyrightText: 2023 Linutronix GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
// we do not want to panic or exit, see explanation in main()
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::expect_used,
        clippy::exit,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::modulo_arithmetic, // % 0 panics - use checked_rem
        clippy::integer_division,  // / 0 panics - use checked_div
        clippy::unreachable,
        clippy::unwrap_in_result,
    )
)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::let_underscore_untyped)]
#![allow(clippy::arc_with_non_send_sync)] // false positive (https://github.com/rust-lang/rust-clippy/issues/11382)
#![allow(clippy::significant_drop_tightening)] // false positive (https://github.com/rust-lang/rust-clippy/issues/11279)

pub mod configuration;
pub mod controller;
pub mod dispatcher;
pub mod interface_setup;
pub mod ptp;
pub mod queue_setup;

#[cfg(feature = "dbus")]
pub mod facade;

// Only for documentation
#[doc = include_str!("../examples/timestamps/README.md")]
pub mod timestamp_example {}
