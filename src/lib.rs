#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

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
