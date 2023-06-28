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
// Some of these lints might be unreasonable for a growing code base,
// but apply to the current state and might be removed later if needed.
#![deny(non_ascii_idents)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![warn(clippy::nursery)]
#![deny(clippy::as_conversions)]
#![deny(clippy::as_underscore)]
#![deny(clippy::assertions_on_result_states)]
#![warn(clippy::create_dir)]
#![warn(clippy::dbg_macro)]
#![warn(clippy::decimal_literal_representation)]
#![deny(clippy::default_union_representation)]
#![warn(clippy::deref_by_slicing)]
#![warn(clippy::empty_drop)]
#![warn(clippy::empty_structs_with_brackets)]
#![warn(clippy::filetype_is_file)]
#![deny(clippy::float_cmp_const)]
#![deny(clippy::fn_to_numeric_cast_any)]
#![deny(clippy::format_push_string)]
#![deny(clippy::if_then_some_else_none)]
#![deny(clippy::impl_trait_in_params)]
#![deny(clippy::integer_division)]
#![warn(clippy::lossy_float_literal)]
#![warn(clippy::map_err_ignore)]
#![deny(clippy::mem_forget)]
#![warn(clippy::missing_trait_methods)]
#![deny(clippy::mixed_read_write_in_expression)]
#![warn(clippy::modulo_arithmetic)]
#![deny(clippy::multiple_inherent_impl)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
#![warn(clippy::mutex_atomic)]
#![warn(clippy::non_ascii_literal)]
#![warn(clippy::partial_pub_fields)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::rc_mutex)]
#![warn(clippy::rest_pat_in_fully_bound_structs)]
#![deny(clippy::same_name_method)]
#![deny(clippy::self_named_module_files)]
#![deny(clippy::unseparated_literal_suffix)]
#![warn(clippy::shadow_unrelated)]
#![warn(clippy::str_to_string)]
#![deny(clippy::string_slice)]
#![deny(clippy::string_to_string)]
#![warn(clippy::suspicious_xor_used_as_pow)]
#![deny(clippy::try_err)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(clippy::unnecessary_safety_comment)]
#![warn(clippy::unnecessary_safety_doc)]
#![deny(clippy::unnecessary_self_imports)]
#![deny(clippy::unneeded_field_pattern)]
#![warn(clippy::verbose_file_reads)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::let_underscore_untyped)]

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
