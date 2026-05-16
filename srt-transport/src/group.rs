// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT socket groups for bonding (SMPTE 2022-7, backup, balancing).
//!
//! Uses libsrt's native socket group API (`srt_create_group`, `srt_connect_group`)
//! to provide multi-link SRT connections with automatic deduplication and failover.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use srt_protocol::received_packet::ReceivedPacket;
use tokio::sync::{mpsc, oneshot, watch};

use srt_protocol::config::{CryptoModeConfig, KeySize, MemberStatus, RetransmitAlgo, SocketStatus, SrtConfig};
use srt_protocol::error::SrtError;
use srt_protocol::stats::SrtStats;

use crate::epoll_bridge::{io_handle, IoCommand, IoHandle, SocketId};

/// Per-member state and statistics snapshot for one link inside an
/// [`SrtGroup`]. Obtained via [`SrtGroup::member_stats`].
#[derive(Debug, Clone)]
pub struct GroupMemberStats {
    /// libsrt member socket ID (opaque handle).
    pub id: SocketId,
    /// Peer address this member is connected to (may be `None` if libsrt
    /// has not yet learned the peer — typical for members in `Pending`).
    pub peer_addr: Option<SocketAddr>,
    /// Underlying SRT socket status (connection state).
    pub socket_status: SocketStatus,
    /// Group-level member status: Pending / Idle (backup standby) / Running
    /// (active) / Broken.
    pub member_status: MemberStatus,
    /// Member priority (backup mode). 0 means "equal priority"; lower
    /// values are preferred when multiple members are healthy.
    pub weight: u16,
    /// Per-member traffic stats — RTT, rates, packet/byte counters,
    /// ARQ, FEC. Zeroed when libsrt reports the member as broken.
    pub stats: SrtStats,
}

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
    recv_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<ReceivedPacket>>,
    status_rx: watch::Receiver<SocketStatus>,
    mode: GroupMode,
    endpoints: Vec<SocketAddr>,
}

impl SrtGroup {
    /// Create a new group builder.
    pub fn builder(mode: GroupMode) -> SrtGroupBuilder {
        SrtGroupBuilder::new(mode)
    }

    /// Send data to all group members.
    ///
    /// Awaits on the bounded channel to the `srt-io` thread for natural
    /// backpressure (same fix as `SrtSocket::send` — see the 2026-04-20
    /// interop report for the `try_send` → reconnect-loop failure mode).
    pub async fn send(&self, data: &[u8]) -> Result<usize, SrtError> {
        let len = data.len();
        self.send_tx
            .send(Bytes::copy_from_slice(data))
            .await
            .map_err(|_| SrtError::ConnectionLost)?;
        Ok(len)
    }

    /// Receive a packet from the group (deduplicated by libsrt),
    /// with sender metadata. Mirrors [`SrtSocket::recv`] — see that
    /// doc for the metadata-aware semantics.
    pub async fn recv(&self) -> Result<ReceivedPacket, SrtError> {
        let mut rx = self.recv_rx.lock().await;
        match rx.recv().await {
            Some(pkt) => Ok(pkt),
            None => Err(SrtError::ConnectionLost),
        }
    }

    /// Legacy-shape recv that discards sender metadata.
    #[allow(dead_code)]
    pub async fn recv_bytes(&self) -> Result<Bytes, SrtError> {
        self.recv().await.map(|p| p.data)
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

    /// Get per-member stats for every link in this bonded group.
    ///
    /// Returns an entry per live (and recently-broken) group member
    /// with its peer address, socket + member status, priority weight,
    /// and SRT stats. Returns an empty vec if the group was closed or
    /// libsrt refused the query.
    pub async fn member_stats(&self) -> Vec<GroupMemberStats> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.io.send_command(IoCommand::GetGroupMemberStats {
            id: self.id,
            reply: reply_tx,
        });
        reply_rx.await.unwrap_or_default()
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

    pub fn receiver_latency(mut self, latency: Duration) -> Self {
        self.config.recv_latency = latency.as_millis() as u32;
        self
    }

    pub fn sender_latency(mut self, latency: Duration) -> Self {
        self.config.peer_latency = latency.as_millis() as u32;
        self
    }

    pub fn input_bw(mut self, bw: i64) -> Self {
        self.config.input_bw = bw;
        self
    }

    pub fn overhead_bw(mut self, pct: i32) -> Self {
        self.config.overhead_bw = pct;
        self
    }

    pub fn enforced_encryption(mut self, enforce: bool) -> Self {
        self.config.enforced_encryption = enforce;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    pub fn send_drop_delay(mut self, delay: i32) -> Self {
        self.config.send_drop_delay = delay;
        self
    }

    pub fn loss_max_ttl(mut self, ttl: i32) -> Self {
        self.config.loss_max_ttl = ttl;
        self
    }

    pub fn km_refresh_rate(mut self, rate: u32) -> Self {
        self.config.km_refresh_rate = rate;
        self
    }

    pub fn km_pre_announce(mut self, packets: u32) -> Self {
        self.config.km_pre_announce = packets;
        self
    }

    pub fn mss(mut self, mss: u32) -> Self {
        self.config.mss = mss;
        self
    }

    pub fn tlpkt_drop(mut self, enable: bool) -> Self {
        self.config.tlpkt_drop = enable;
        self
    }

    pub fn ip_ttl(mut self, ttl: i32) -> Self {
        self.config.ip_ttl = ttl;
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
        let (send_tx, send_rx) = mpsc::channel(8192);
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
