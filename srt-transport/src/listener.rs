// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT listener for accepting incoming connections.
//!
//! Binds to a local address and accepts incoming SRT connections.
//! Each accepted connection returns an [`SrtSocket`].

use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};

use srt_protocol::access_control::{AccessControl, AccessControlFn};
use srt_protocol::config::{CryptoModeConfig, KeySize, RetransmitAlgo, SocketStatus, SrtConfig};
use srt_protocol::error::{RejectReason, SrtError};

use crate::epoll_bridge::{io_handle, IoCommand, IoHandle, SocketId};
use crate::socket::SrtSocket;

/// An SRT listener that accepts incoming connections.
pub struct SrtListener {
    id: SocketId,
    io: IoHandle,
    accept_rx: mpsc::Receiver<SocketId>,
    local_addr: SocketAddr,
}

impl SrtListener {
    /// Create a new listener builder.
    pub fn builder() -> SrtListenerBuilder {
        SrtListenerBuilder::new()
    }

    /// Accept a new incoming connection.
    ///
    /// Returns an `SrtSocket` representing the accepted connection.
    pub async fn accept(&mut self) -> Result<SrtSocket, SrtError> {
        match self.accept_rx.recv().await {
            Some(sock_id) => SrtSocket::from_accepted(sock_id).await,
            None => Err(SrtError::SocketClosed),
        }
    }

    /// Get the local address this listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Close the listener.
    pub async fn close(&self) -> Result<(), SrtError> {
        self.io.send_command(IoCommand::Close { id: self.id });
        Ok(())
    }
}

impl Drop for SrtListener {
    fn drop(&mut self) {
        self.io.send_command(IoCommand::Close { id: self.id });
    }
}

/// Builder for creating an SRT listener.
pub struct SrtListenerBuilder {
    config: SrtConfig,
    backlog: i32,
    access_control: Option<Box<dyn AccessControl>>,
}

impl SrtListenerBuilder {
    pub fn new() -> Self {
        Self {
            config: SrtConfig::default(),
            backlog: 5,
            access_control: None,
        }
    }

    pub fn latency(mut self, latency: Duration) -> Self {
        let ms = latency.as_millis() as u32;
        self.config.recv_latency = ms;
        self.config.peer_latency = ms;
        self
    }

    pub fn sender_latency(mut self, latency: Duration) -> Self {
        self.config.peer_latency = latency.as_millis() as u32;
        self
    }

    pub fn receiver_latency(mut self, latency: Duration) -> Self {
        self.config.recv_latency = latency.as_millis() as u32;
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

    pub fn mss(mut self, mss: u32) -> Self {
        self.config.mss = mss;
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

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    pub fn live_mode(mut self) -> Self {
        self.config.live_defaults();
        self
    }

    pub fn file_mode(mut self) -> Self {
        self.config.file_defaults();
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

    pub fn input_bw(mut self, bw: i64) -> Self {
        self.config.input_bw = bw;
        self
    }

    pub fn overhead_bw(mut self, pct: i32) -> Self {
        self.config.overhead_bw = pct;
        self
    }

    pub fn max_rexmit_bw(mut self, bw: i64) -> Self {
        self.config.max_rexmit_bw = bw;
        self
    }

    pub fn enforced_encryption(mut self, enforce: bool) -> Self {
        self.config.enforced_encryption = enforce;
        self
    }

    pub fn payload_size(mut self, size: u32) -> Self {
        self.config.payload_size = size;
        self
    }

    pub fn ip_tos(mut self, tos: i32) -> Self {
        self.config.ip_tos = tos;
        self
    }

    pub fn ip_ttl(mut self, ttl: i32) -> Self {
        self.config.ip_ttl = ttl;
        self
    }

    pub fn retransmit_algo(mut self, algo: RetransmitAlgo) -> Self {
        self.config.retransmit_algo = algo;
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

    pub fn tlpkt_drop(mut self, enable: bool) -> Self {
        self.config.tlpkt_drop = enable;
        self
    }

    /// Set the listen backlog.
    pub fn backlog(mut self, n: i32) -> Self {
        self.backlog = n;
        self
    }

    /// Set access control via a trait object.
    pub fn access_control(mut self, ac: impl AccessControl) -> Self {
        self.access_control = Some(Box::new(ac));
        self
    }

    /// Set access control via a closure.
    pub fn access_control_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&srt_protocol::access_control::HandshakeInfo) -> Result<(), RejectReason>
            + Send
            + Sync
            + 'static,
    {
        self.access_control = Some(Box::new(AccessControlFn(f)));
        self
    }

    /// Enable group connections on this listener (for bonding).
    pub fn group_connect(mut self, enable: bool) -> Self {
        self.config.group_connect = enable;
        self
    }

    /// Bind and start listening.
    pub async fn bind(self, addr: SocketAddr) -> Result<SrtListener, SrtError> {
        let io = io_handle();

        // Create socket
        let (create_tx, create_rx) = oneshot::channel();
        io.send_command(IoCommand::CreateSocket {
            config: self.config,
            reply: create_tx,
        });
        let id = create_rx.await.map_err(|_| SrtError::SocketFail)??;

        // Register accept channel and access control
        let (accept_tx, accept_rx) = mpsc::channel(16);
        io.send_command(IoCommand::RegisterListener {
            id,
            accept_tx,
            access_control: self.access_control,
        });

        // Register status channel (for listener state tracking)
        let (_recv_tx, _recv_rx) = mpsc::unbounded_channel();
        let (_send_tx, _send_rx) = mpsc::channel(1);
        let (status_tx, _status_rx) = watch::channel(SocketStatus::Init);
        io.send_command(IoCommand::RegisterSocket {
            id,
            recv_tx: _recv_tx,
            send_rx: _send_rx,
            status_tx,
        });

        // Bind
        let (bind_tx, bind_rx) = oneshot::channel();
        io.send_command(IoCommand::Bind {
            id,
            addr,
            reply: bind_tx,
        });
        bind_rx.await.map_err(|_| SrtError::SocketFail)??;

        // Listen
        let (listen_tx, listen_rx) = oneshot::channel();
        io.send_command(IoCommand::Listen {
            id,
            backlog: self.backlog,
            reply: listen_tx,
        });
        listen_rx.await.map_err(|_| SrtError::SocketFail)??;

        // Get actual bound address
        let (addr_tx, addr_rx) = oneshot::channel();
        io.send_command(IoCommand::GetLocalAddr { id, reply: addr_tx });
        let local_addr = addr_rx.await.unwrap_or(None).unwrap_or(addr);

        Ok(SrtListener {
            id,
            io,
            accept_rx,
            local_addr,
        })
    }
}

impl Default for SrtListenerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
