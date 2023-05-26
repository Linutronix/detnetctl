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

pub mod configuration;
pub mod controller;
pub mod guard;
pub mod interface_setup;
pub mod queue_setup;

#[cfg(feature = "dbus")]
pub mod facade;

// Only for documentation
#[doc = include_str!("../examples/timestamps/README.md")]
pub mod timestamp_example {}
