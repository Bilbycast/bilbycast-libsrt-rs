// Copyright (c) 2026 Reza Rahimi / Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT socket groups for bonding (SMPTE 2022-7, backup, balancing).
//!
//! Uses libsrt's native socket group API (`srt_create_group`, `srt_connect_group`)
//! to provide multi-link SRT connections with automatic deduplication and failover.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, watch};

use srt_protocol::config::{CryptoModeConfig, KeySize, RetransmitAlgo, SocketStatus, SrtConfig};
use srt_protocol::error::SrtError;
use srt_protocol::stats::SrtStats;

use crate::epoll_bridge::{io_handle, IoCommand, IoHandle, SocketId};

/// SRT group modes for bonding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMode {
    /// All links active simultaneously — SMPTE 2022-7 hitless redundancy.
    Broadcast,
    /// Primary/backup with automatic failover.
    Backup,
}

impl GroupMode {
    pub(crate) fn to_srt_type(self) -> libsrt_sys::SRT_GROUP_TYPE {
        match self {
            GroupMode::Broadcast => libsrt_sys::SRT_GTYPE_BROADCAST,
            GroupMode::Backup => libsrt_sys::SRT_GTYPE_BACKUP,
        }
    }
}

/// An SRT socket group for bonded connections.
///
/// A group behaves like a single socket but sends/receives over multiple
/// network paths simultaneously. libsrt handles deduplication internally.
pub struct SrtGroup {
    id: SocketId,
    io: IoHandle,
    send_tx: mpsc::Sender<Bytes>,
    recv_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Bytes>>,
    status_rx: watch::Receiver<SocketStatus>,
    mode: GroupMode,
    endpoints: Vec<SocketAddr>,
}

impl SrtGroup {
    /// Create a new group builder.
    pub fn builder(mode: GroupMode) -> SrtGroupBuilder {
        SrtGroupBuilder::new(mode)
    }

    /// Send data to all group members (fire-and-forget via bounded channel).
    pub async fn send(&self, data: &[u8]) -> Result<usize, SrtError> {
        let len = data.len();
        self.send_tx
            .try_send(Bytes::copy_from_slice(data))
            .map_err(|_| SrtError::AsyncSend)?;
        Ok(len)
    }

    /// Receive data from the group (deduplicated by libsrt).
    pub async fn recv(&self) -> Result<Bytes, SrtError> {
        let mut rx = self.recv_rx.lock().await;
        match rx.recv().await {
            Some(data) => Ok(data),
            None => Err(SrtError::ConnectionLost),
        }
    }

    /// Get aggregate group statistics.
    pub async fn stats(&self) -> SrtStats {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.io.send_command(IoCommand::GetStats {
            id: self.id,
            reply: reply_tx,
        });
        reply_rx.await.unwrap_or_else(|_| Ok(SrtStats::default())).unwrap_or_default()
    }

    /// Get the group mode.
    pub fn mode(&self) -> GroupMode {
        self.mode
    }

    /// Get the endpoints this group is connected to.
    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.endpoints
    }

    /// Get the current group status.
    pub fn status(&self) -> SocketStatus {
        *self.status_rx.borrow()
    }

    /// Close the group and all member sockets.
    pub async fn close(&self) -> Result<(), SrtError> {
        self.io.send_command(IoCommand::Close { id: self.id });
        Ok(())
    }
}

impl Drop for SrtGroup {
    fn drop(&mut self) {
        self.io.send_command(IoCommand::Close { id: self.id });
    }
}

/// Builder for SRT socket groups.
pub struct SrtGroupBuilder {
    mode: GroupMode,
    config: SrtConfig,
    endpoints: Vec<SocketAddr>,
}

impl SrtGroupBuilder {
    pub fn new(mode: GroupMode) -> Self {
        Self {
            mode,
            config: SrtConfig::default(),
            endpoints: Vec::new(),
        }
    }

    /// Add an endpoint to the group.
    pub fn add_endpoint(mut self, addr: SocketAddr) -> Self {
        self.endpoints.push(addr);
        self
    }

    // ── Same builder options as SrtSocketBuilder ──

    pub fn latency(mut self, latency: Duration) -> Self {
        let ms = latency.as_millis() as u32;
        self.config.recv_latency = ms;
        self.config.peer_latency = ms;
        self
    }

    pub fn encryption(mut self, passphrase: &str, key_size: KeySize) -> Self {
        self.config.passphrase = passphrase.to_string();
        self.config.key_size = key_size;
        self
    }

    pub fn crypto_mode(mut self, mode: CryptoModeConfig) -> Self {
        self.config.crypto_mode = mode;
        self
    }

    pub fn live_mode(mut self) -> Self {
        self.config.live_defaults();
        self
    }

    pub fn stream_id(mut self, id: String) -> Self {
        self.config.stream_id = id;
        self
    }

    pub fn packet_filter(mut self, filter: String) -> Self {
        self.config.packet_filter = filter;
        self
    }

    pub fn max_bw(mut self, bw: i64) -> Self {
        self.config.max_bw = bw;
        self
    }

    pub fn max_rexmit_bw(mut self, bw: i64) -> Self {
        self.config.max_rexmit_bw = bw;
        self
    }

    pub fn flight_flag_size(mut self, size: u32) -> Self {
        self.config.flight_flag_size = size;
        self
    }

    pub fn send_buffer_size(mut self, size: u32) -> Self {
        self.config.send_buffer_size = size;
        self
    }

    pub fn recv_buffer_size(mut self, size: u32) -> Self {
        self.config.recv_buffer_size = size;
        self
    }

    pub fn peer_idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.peer_idle_timeout = timeout;
        self
    }

    pub fn ip_tos(mut self, tos: i32) -> Self {
        self.config.ip_tos = tos;
        self
    }

    pub fn payload_size(mut self, size: u32) -> Self {
        self.config.payload_size = size;
        self
    }

    pub fn retransmit_algo(mut self, algo: RetransmitAlgo) -> Self {
        self.config.retransmit_algo = algo;
        self
    }

    /// Connect the group to all configured endpoints.
    pub async fn connect(self) -> Result<Arc<SrtGroup>, SrtError> {
        if self.endpoints.is_empty() {
            return Err(SrtError::InvalidParam);
        }

        let io = io_handle();

        // Create group
        let (create_tx, create_rx) = oneshot::channel();
        io.send_command(IoCommand::CreateGroup {
            mode: self.mode.to_srt_type(),
            config: self.config,
            reply: create_tx,
        });
        let id = create_rx.await.map_err(|_| SrtError::SocketFail)??;

        // Register channels
        let (recv_tx, recv_rx) = mpsc::unbounded_channel();
        let (send_tx, send_rx) = mpsc::channel(256);
        let (status_tx, status_rx) = watch::channel(SocketStatus::Init);
        io.send_command(IoCommand::RegisterSocket {
            id,
            recv_tx,
            send_rx,
            status_tx,
        });

        // Connect group to endpoints
        let (conn_tx, conn_rx) = oneshot::channel();
        io.send_command(IoCommand::ConnectGroup {
            id,
            endpoints: self.endpoints.clone(),
            reply: conn_tx,
        });
        conn_rx.await.map_err(|_| SrtError::SocketFail)??;

        Ok(Arc::new(SrtGroup {
            id,
            io,
            send_tx,
            recv_rx: tokio::sync::Mutex::new(recv_rx),
            status_rx,
            mode: self.mode,
            endpoints: self.endpoints,
        }))
    }
}
