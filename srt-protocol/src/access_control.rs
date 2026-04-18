// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Access control for SRT listener connections.
//!
//! Provides the [`AccessControl`] trait for inspecting incoming connection
//! metadata (peer address, Stream ID, encryption state) and deciding whether
//! to accept or reject.
//!
//! This maps to libsrt's `srt_listen_callback()` mechanism.

use std::net::SocketAddr;

use crate::error::RejectReason;

/// Information about an incoming connection, provided to the access control callback.
#[derive(Debug, Clone)]
pub struct HandshakeInfo {
    /// Remote peer address.
    pub peer_addr: SocketAddr,
    /// Stream ID sent by the caller (empty if none).
    pub stream_id: String,
    /// Whether the caller is using encryption.
    pub is_encrypted: bool,
    /// The caller's SRT socket ID.
    pub peer_socket_id: u32,
    /// The caller's SRT version (from the handshake).
    pub peer_version: i32,
}

/// Trait for controlling access to an SRT listener.
///
/// Implement this trait to inspect incoming connections and decide
/// whether to accept or reject them.
pub trait AccessControl: Send + Sync + 'static {
    /// Called when a new connection completes the handshake.
    ///
    /// Return `Ok(())` to accept or `Err(RejectReason)` to reject.
    fn on_accept(&self, info: &HandshakeInfo) -> Result<(), RejectReason>;
}

/// An access control implementation that accepts all connections (default).
pub struct AcceptAll;

impl AccessControl for AcceptAll {
    fn on_accept(&self, _info: &HandshakeInfo) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// Access control via a closure.
pub struct AccessControlFn<F>(pub F);

impl<F> AccessControl for AccessControlFn<F>
where
    F: Fn(&HandshakeInfo) -> Result<(), RejectReason> + Send + Sync + 'static,
{
    fn on_accept(&self, info: &HandshakeInfo) -> Result<(), RejectReason> {
        (self.0)(info)
    }
}

/// Maximum Stream ID length in bytes (per SRT spec).
pub const SRT_MAX_STREAM_ID_LEN: usize = 512;

/// Parsed SRT Access Control Stream ID.
///
/// Represents the structured `#!::key=value,...` format defined by the
/// SRT Access Control specification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamIdInfo {
    pub resource: Option<String>,
    pub mode: Option<String>,
    pub session_id: Option<String>,
    pub content_type: Option<String>,
    pub user_name: Option<String>,
    pub host_name: Option<String>,
    pub extra: Vec<(String, String)>,
    pub raw: String,
}

/// SRT Access Control mode values.
pub mod stream_mode {
    pub const REQUEST: &str = "request";
    pub const PUBLISH: &str = "publish";
    pub const BIDIRECTIONAL: &str = "bidirectional";
}

/// SRT Access Control type values.
pub mod stream_type {
    pub const STREAM: &str = "stream";
    pub const FILE: &str = "file";
    pub const AUTH: &str = "auth";
}

impl StreamIdInfo {
    /// Parse a Stream ID string into structured fields.
    pub fn parse(stream_id: &str) -> Self {
        let mut info = StreamIdInfo {
            raw: stream_id.to_string(),
            ..Default::default()
        };

        if stream_id.is_empty() {
            return info;
        }

        if let Some(params) = stream_id.strip_prefix("#!::") {
            for pair in params.split(',') {
                let pair = pair.trim();
                if pair.is_empty() {
                    continue;
                }
                if let Some((key, value)) = pair.split_once('=') {
                    match key {
                        "r" => info.resource = Some(value.to_string()),
                        "m" => info.mode = Some(value.to_string()),
                        "s" => info.session_id = Some(value.to_string()),
                        "t" => info.content_type = Some(value.to_string()),
                        "u" => info.user_name = Some(value.to_string()),
                        "h" => info.host_name = Some(value.to_string()),
                        _ => info.extra.push((key.to_string(), value.to_string())),
                    }
                }
            }
        } else {
            info.resource = Some(stream_id.to_string());
        }

        info
    }

    /// Format this info back into the SRT Access Control string format.
    pub fn to_stream_id(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref r) = self.resource {
            parts.push(format!("r={r}"));
        }
        if let Some(ref m) = self.mode {
            parts.push(format!("m={m}"));
        }
        if let Some(ref s) = self.session_id {
            parts.push(format!("s={s}"));
        }
        if let Some(ref t) = self.content_type {
            parts.push(format!("t={t}"));
        }
        if let Some(ref u) = self.user_name {
            parts.push(format!("u={u}"));
        }
        if let Some(ref h) = self.host_name {
            parts.push(format!("h={h}"));
        }
        for (k, v) in &self.extra {
            parts.push(format!("{k}={v}"));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("#!::{}", parts.join(","))
        }
    }
}
