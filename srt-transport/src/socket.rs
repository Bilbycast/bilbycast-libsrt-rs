// Copyright (c) 2026 Reza Rahimi / Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT socket handle with builder pattern.
//!
//! Provides the main user-facing interface for SRT connections.
//! Communicates with the I/O thread via channels — zero mutex acquisitions
//! on send/recv hot paths (except the uncontended recv Mutex).

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, watch};

use srt_protocol::config::{CryptoModeConfig, KeySize, RetransmitAlgo, SocketStatus, SrtConfig};
use srt_protocol::error::SrtError;
use srt_protocol::stats::SrtStats;

use crate::epoll_bridge::{io_handle, IoCommand, IoHandle, SocketId};

/// An SRT socket connected to a peer.
///
/// All I/O operations are async and communicate with the dedicated I/O thread
/// via channels. `SrtSocket` is `Send + Sync`.
/// Bounded send channel capacity. Matches the edge's output send task channel.
/// If the I/O thread can't keep up, packets are dropped (broadcast-grade behaviour).
const SEND_CHANNEL_CAPACITY: usize = 256;

pub struct SrtSocket {
    id: SocketId,
    io: IoHandle,
    send_tx: mpsc::Sender<Bytes>,
    recv_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Bytes>>,
    status_rx: watch::Receiver<SocketStatus>,
    local_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
    stream_id: String,
}

impl SrtSocket {
    /// Create a new builder with default configuration.
    pub fn builder() -> SrtSocketBuilder {
        SrtSocketBuilder::new()
    }

    /// Create from a raw accepted socket ID (used by SrtListener).
    pub(crate) async fn from_accepted(id: SocketId) -> Result<Self, SrtError> {
        let io = io_handle();

        // Register channels
        let (recv_tx, recv_rx) = mpsc::unbounded_channel();
        let (send_tx, send_rx) = mpsc::channel(SEND_CHANNEL_CAPACITY);
        let (status_tx, status_rx) = watch::channel(SocketStatus::Connected);

        io.send_command(IoCommand::RegisterSocket {
            id,
            recv_tx,
            send_rx,
            status_tx,
        });

        // Get addresses and stream ID
        let (local_tx, local_rx) = oneshot::channel();
        let (peer_tx, peer_rx) = oneshot::channel();
        let (sid_tx, sid_rx) = oneshot::channel();

        io.send_command(IoCommand::GetLocalAddr { id, reply: local_tx });
        io.send_command(IoCommand::GetPeerAddr { id, reply: peer_tx });
        io.send_command(IoCommand::GetStreamId { id, reply: sid_tx });

        let local_addr = local_rx.await.unwrap_or(None).unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let peer_addr = peer_rx.await.unwrap_or(None);
        let stream_id = sid_rx.await.unwrap_or_default();

        Ok(SrtSocket {
            id,
            io,
            send_tx,
            recv_rx: tokio::sync::Mutex::new(recv_rx),
            status_rx,
            local_addr,
            peer_addr,
            stream_id,
        })
    }

    /// Send data to the peer.
    ///
    /// Fire-and-forget: data is pushed into a bounded channel that the I/O thread
    /// drains. If the channel is full (I/O thread can't keep up), the oldest
    /// unsent data is in the channel and this returns the byte count immediately.
    /// The I/O thread handles the actual `srt_sendmsg2` call.
    pub async fn send(&self, data: &[u8]) -> Result<usize, SrtError> {
        let len = data.len();
        self.send_tx
            .try_send(Bytes::copy_from_slice(data))
            .map_err(|_| SrtError::AsyncSend)?;
        Ok(len)
    }

    /// Receive data from the peer.
    pub async fn recv(&self) -> Result<Bytes, SrtError> {
        let mut rx = self.recv_rx.lock().await;
        match rx.recv().await {
            Some(data) => Ok(data),
            None => Err(SrtError::ConnectionLost),
        }
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the peer address.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Get the Stream ID.
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    /// Get performance statistics.
    pub async fn stats(&self) -> SrtStats {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.io.send_command(IoCommand::GetStats {
            id: self.id,
            reply: reply_tx,
        });
        reply_rx.await.unwrap_or_else(|_| Ok(SrtStats::default())).unwrap_or_default()
    }

    /// Get the current socket status.
    pub fn status(&self) -> SocketStatus {
        *self.status_rx.borrow()
    }

    /// Wait for the socket to reach a specific status.
    pub async fn wait_for_state(&self, target: SocketStatus) -> SocketStatus {
        let mut rx = self.status_rx.clone();
        loop {
            let current = *rx.borrow();
            if current == target || current == SocketStatus::Broken || current == SocketStatus::Closed {
                return current;
            }
            if rx.changed().await.is_err() {
                return *rx.borrow();
            }
        }
    }

    /// Close the socket gracefully.
    pub async fn close(&self) -> Result<(), SrtError> {
        self.io.send_command(IoCommand::Close { id: self.id });
        Ok(())
    }
}

impl Drop for SrtSocket {
    fn drop(&mut self) {
        self.io.send_command(IoCommand::Close { id: self.id });
    }
}

/// Builder for configuring and creating SRT sockets.
pub struct SrtSocketBuilder {
    config: SrtConfig,
    bind_addr: Option<SocketAddr>,
}

impl SrtSocketBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: SrtConfig::default(),
            bind_addr: None,
        }
    }

    /// Set the receiver-side latency.
    pub fn latency(mut self, latency: Duration) -> Self {
        let ms = latency.as_millis() as u32;
        self.config.recv_latency = ms;
        self.config.peer_latency = ms;
        self
    }

    /// Set the sender-side latency.
    pub fn sender_latency(mut self, latency: Duration) -> Self {
        self.config.peer_latency = latency.as_millis() as u32;
        self
    }

    /// Set the receiver-side latency.
    pub fn receiver_latency(mut self, latency: Duration) -> Self {
        self.config.recv_latency = latency.as_millis() as u32;
        self
    }

    /// Enable encryption.
    pub fn encryption(mut self, passphrase: &str, key_size: KeySize) -> Self {
        self.config.passphrase = passphrase.to_string();
        self.config.key_size = key_size;
        self
    }

    /// Set the encryption cipher mode.
    pub fn crypto_mode(mut self, mode: CryptoModeConfig) -> Self {
        self.config.crypto_mode = mode;
        self
    }

    /// Set the maximum segment size.
    pub fn mss(mut self, mss: u32) -> Self {
        self.config.mss = mss;
        self
    }

    /// Set the flight flag size (flow control window).
    pub fn flight_flag_size(mut self, size: u32) -> Self {
        self.config.flight_flag_size = size;
        self
    }

    /// Set the send buffer size in bytes.
    pub fn send_buffer_size(mut self, size: u32) -> Self {
        self.config.send_buffer_size = size;
        self
    }

    /// Set the receive buffer size in bytes.
    pub fn recv_buffer_size(mut self, size: u32) -> Self {
        self.config.recv_buffer_size = size;
        self
    }

    /// Set the peer idle timeout.
    pub fn peer_idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.peer_idle_timeout = timeout;
        self
    }

    /// Set the connection timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Set live transmission mode (default).
    pub fn live_mode(mut self) -> Self {
        self.config.live_defaults();
        self
    }

    /// Set file transmission mode.
    pub fn file_mode(mut self) -> Self {
        self.config.file_defaults();
        self
    }

    /// Set the Stream ID.
    pub fn stream_id(mut self, id: String) -> Self {
        self.config.stream_id = id;
        self
    }

    /// Set the packet filter (FEC) configuration.
    pub fn packet_filter(mut self, filter: String) -> Self {
        self.config.packet_filter = filter;
        self
    }

    /// Set the maximum bandwidth in bytes/sec.
    pub fn max_bw(mut self, bw: i64) -> Self {
        self.config.max_bw = bw;
        self
    }

    /// Set the estimated input bandwidth in bytes/sec.
    pub fn input_bw(mut self, bw: i64) -> Self {
        self.config.input_bw = bw;
        self
    }

    /// Set the overhead bandwidth percentage.
    pub fn overhead_bw(mut self, pct: i32) -> Self {
        self.config.overhead_bw = pct;
        self
    }

    /// Set the maximum retransmission bandwidth in bytes/sec.
    pub fn max_rexmit_bw(mut self, bw: i64) -> Self {
        self.config.max_rexmit_bw = bw;
        self
    }

    /// Enforce encryption (reject unencrypted peers).
    pub fn enforced_encryption(mut self, enforce: bool) -> Self {
        self.config.enforced_encryption = enforce;
        self
    }

    /// Set the payload size.
    pub fn payload_size(mut self, size: u32) -> Self {
        self.config.payload_size = size;
        self
    }

    /// Set IP Type of Service (DSCP).
    pub fn ip_tos(mut self, tos: i32) -> Self {
        self.config.ip_tos = tos;
        self
    }

    /// Set IP Time-To-Live.
    pub fn ip_ttl(mut self, ttl: i32) -> Self {
        self.config.ip_ttl = ttl;
        self
    }

    /// Set the retransmission algorithm.
    pub fn retransmit_algo(mut self, algo: RetransmitAlgo) -> Self {
        self.config.retransmit_algo = algo;
        self
    }

    /// Set the send drop delay in milliseconds.
    pub fn send_drop_delay(mut self, delay: i32) -> Self {
        self.config.send_drop_delay = delay;
        self
    }

    /// Set the loss max TTL (reorder tolerance).
    pub fn loss_max_ttl(mut self, ttl: i32) -> Self {
        self.config.loss_max_ttl = ttl;
        self
    }

    /// Set the key material refresh rate (packets).
    pub fn km_refresh_rate(mut self, rate: u32) -> Self {
        self.config.km_refresh_rate = rate;
        self
    }

    /// Set the key material pre-announce (packets before refresh).
    pub fn km_pre_announce(mut self, packets: u32) -> Self {
        self.config.km_pre_announce = packets;
        self
    }

    /// Enable/disable too-late packet drop.
    pub fn tlpkt_drop(mut self, enable: bool) -> Self {
        self.config.tlpkt_drop = enable;
        self
    }

    /// Enable rendezvous mode.
    pub fn rendezvous(mut self, enable: bool) -> Self {
        self.config.rendezvous = enable;
        self
    }

    /// Set the local bind address.
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Connect to a remote SRT peer.
    pub async fn connect(self, remote: SocketAddr) -> Result<SrtSocket, SrtError> {
        let io = io_handle();

        // Create socket
        let (create_tx, create_rx) = oneshot::channel();
        io.send_command(IoCommand::CreateSocket {
            config: self.config.clone(),
            reply: create_tx,
        });
        let id = create_rx.await.map_err(|_| SrtError::SocketFail)??;

        // Register channels
        let (recv_tx, recv_rx) = mpsc::unbounded_channel();
        let (send_tx, send_rx) = mpsc::channel(SEND_CHANNEL_CAPACITY);
        let (status_tx, status_rx) = watch::channel(SocketStatus::Init);
        io.send_command(IoCommand::RegisterSocket {
            id,
            recv_tx,
            send_rx,
            status_tx,
        });

        // Wrap bind+connect in a block so we can clean up the I/O thread
        // socket on any failure (otherwise it leaks as a zombie).
        let result = async {
            // Bind if specified
            if let Some(bind_addr) = self.bind_addr {
                let (bind_tx, bind_rx) = oneshot::channel();
                io.send_command(IoCommand::Bind {
                    id,
                    addr: bind_addr,
                    reply: bind_tx,
                });
                bind_rx.await.map_err(|_| SrtError::SocketFail)??;
            }

            // Connect
            let (conn_tx, conn_rx) = oneshot::channel();
            io.send_command(IoCommand::Connect {
                id,
                addr: remote,
                reply: conn_tx,
            });
            // Hard deadline above libsrt's own SRTO_CONNTIMEO (default 3 s).
            // On macOS with a loopback target whose UDP port is closed, libsrt
            // can leave the socket in SRTS_CONNECTING indefinitely — no
            // EPOLL_CONNECT event, no state transition to Broken. Without this
            // wrapper the `conn_rx` oneshot would never be fulfilled and the
            // caller's retry loop would wedge on its first attempt.
            let connect_budget = self.config.connect_timeout + Duration::from_secs(2);
            match tokio::time::timeout(connect_budget, conn_rx).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(e))) => return Err(e),
                Ok(Err(_)) => return Err(SrtError::SocketFail),
                Err(_) => return Err(SrtError::Timeout),
            }

            Ok::<(), SrtError>(())
        }
        .await;

        if let Err(e) = result {
            io.send_command(IoCommand::Close { id });
            return Err(e);
        }

        // Get addresses
        let (local_tx, local_rx) = oneshot::channel();
        let (peer_tx, peer_rx) = oneshot::channel();

        io.send_command(IoCommand::GetLocalAddr { id, reply: local_tx });
        io.send_command(IoCommand::GetPeerAddr { id, reply: peer_tx });

        let local_addr = local_rx.await.unwrap_or(None).unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let peer_addr = peer_rx.await.unwrap_or(None);

        Ok(SrtSocket {
            id,
            io,
            send_tx,
            recv_rx: tokio::sync::Mutex::new(recv_rx),
            status_rx,
            local_addr,
            peer_addr,
            stream_id: self.config.stream_id.clone(),
        })
    }

    /// Connect in rendezvous mode.
    pub async fn connect_rendezvous(
        mut self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<SrtSocket, SrtError> {
        self.config.rendezvous = true;
        self.bind_addr = Some(local);
        self.connect(remote).await
    }
}

impl Default for SrtSocketBuilder {
    fn default() -> Self {
        Self::new()
    }
}
