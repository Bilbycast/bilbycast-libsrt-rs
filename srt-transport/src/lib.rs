// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Async I/O transport layer wrapping Haivision libsrt.
//!
//! This crate provides [`SrtSocket`], [`SrtListener`], and [`SrtGroup`] types
//! for building SRT applications on top of [tokio](https://tokio.rs/). It wraps
//! the Haivision libsrt C library via a dedicated I/O thread with epoll,
//! bridged to Tokio async tasks via channels.
//!
//! # Quick Start
//!
//! ```no_run
//! use srt_transport::SrtSocket;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Connect to a remote SRT peer
//! let socket = SrtSocket::builder()
//!     .latency(Duration::from_millis(120))
//!     .live_mode()
//!     .connect("127.0.0.1:4200".parse()?)
//!     .await?;
//!
//! // Send data
//! socket.send(b"Hello SRT!").await?;
//!
//! // Receive data
//! let data = socket.recv().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Architecture
//!
//! All libsrt C API calls happen on a single dedicated OS thread (the "I/O thread").
//! Tokio tasks communicate with it via lock-free channels. This eliminates the
//! need for any Mutex on the data path and ensures thread safety (libsrt sockets
//! are not safe for concurrent access).
//!
//! # Bonding
//!
//! [`SrtGroup`] provides native SRT bonding via libsrt's socket group API:
//! - `Broadcast` mode: SMPTE 2022-7 hitless redundancy (all links active)
//! - `Backup` mode: primary/backup with automatic failover
//! - `Balancing` mode: load balancing across links

pub(crate) mod epoll_bridge;
pub(crate) mod error;
pub(crate) mod stats_bridge;

pub mod socket;
pub mod listener;
pub mod group;

pub use srt_protocol;

/// Identifies the compiled SRT backend at runtime. Edge-side validation uses
/// this to warn about interop caveats that only apply to one backend (e.g.
/// the pure-Rust FEC+encryption ordering bug).
pub const BACKEND_NAME: &str = "libsrt";

// Re-exports for convenience (matching bilbycast-srt/srt-transport API)
pub use socket::{SrtSocket, SrtSocketBuilder};
pub use listener::{SrtListener, SrtListenerBuilder};
pub use group::{GroupMemberStats, GroupMode, SrtGroup, SrtGroupBuilder};
pub use srt_protocol::config::MemberStatus;
pub use srt_protocol::access_control::{AccessControl, AccessControlFn, HandshakeInfo};
