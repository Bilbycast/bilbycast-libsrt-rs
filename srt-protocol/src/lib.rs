// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT protocol types for the libsrt wrapper.
//!
//! This crate provides pure-Rust data types (config, stats, errors, access control)
//! that are API-compatible with the bilbycast-srt `srt-protocol` crate. No dependency
//! on libsrt or any C library — these are just data structures and traits.

pub mod access_control;
pub mod config;
pub mod error;
pub mod fec;
pub mod received_packet;
pub mod stats;

// Re-exports for convenience (must match bilbycast-srt/srt-protocol exactly)
pub use config::{KeySize, SrtConfig, SocketStatus, TransType};
pub use error::{RejectReason, SrtError};
pub use received_packet::ReceivedPacket;
pub use stats::SrtStats;
