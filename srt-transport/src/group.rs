// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT socket groups for bonding (SMPTE 2022-7, backup, balancing).
//!
//! Uses libsrt's native socket group API (`srt_create_group`, `srt_connect_group`)
//! to provide multi-link SRT connections with automatic deduplication and failover.
//!
//! # Members are not self-healing
//!
//! libsrt removes a broken member from its group and leaves bringing it back
//! to the application (vendored `docs/features/socket-groups.md`, "the
//! application should reconnect it"). [`SrtGroup::add_member`] is that
//! reconnect: it prepares one endpoint exactly as the initial connect did —
//! same source address, weight and token — and hands it to
//! `srt_connect_group`, which is what upstream's own `testing/testmedia.cpp`
//! does. Each member carries a caller-chosen *token* ([`GroupEndpoint::token`],
//! read back on [`GroupMemberStats::token`]) so a member listed by
//! [`SrtGroup::member_stats`] can be matched to the endpoint that created it.

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

/// The greatest member weight libsrt accepts (`CUDT::MAX_WEIGHT`,
/// vendored `srtcore/core.h`). A weight above it makes libsrt refuse the
/// **whole** `srt_connect_group` call, not just that member.
pub const MAX_GROUP_MEMBER_WEIGHT: u16 = 32767;

/// One member link to connect into an [`SrtGroup`]: the target, an optional
/// source address to bind, the member's libsrt weight and its token.
///
/// - `local_addr` — bound before connecting, so the member leaves from that
///   source IP (and port, when non-zero). The kernel still routes by its
///   table; this is a source-address pin, not `SO_BINDTODEVICE`. `None`
///   leaves the member unbound. Must be the same address family as `addr`.
/// - `weight` — libsrt's member weight: in backup mode the **greater** weight
///   is preferred, `0..=`[`MAX_GROUP_MEMBER_WEIGHT`]. Broadcast mode ignores
///   it. It travels in the group handshake, so a listener's mirror group
///   sees it too.
/// - `token` — an opaque, caller-chosen identifier libsrt stores on the
///   member and reports back in [`GroupMemberStats::token`]. It never goes on
///   the wire. Must be `>= 0` (libsrt reads `-1` as "generate one for me").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupEndpoint {
    pub addr: SocketAddr,
    pub local_addr: Option<SocketAddr>,
    pub weight: u16,
    pub token: i32,
}

impl GroupEndpoint {
    /// An unbound member with weight 0.
    pub fn new(addr: SocketAddr, token: i32) -> Self {
        Self {
            addr,
            local_addr: None,
            weight: 0,
            token,
        }
    }

    /// Refuse what libsrt would refuse for the whole group call (a source of
    /// a different family from the target, a weight above
    /// [`MAX_GROUP_MEMBER_WEIGHT`]) and a negative token, which libsrt would
    /// replace with one of its own and so break matching.
    pub fn check(&self) -> Result<(), SrtError> {
        if let Some(local) = self.local_addr {
            if local.is_ipv4() != self.addr.is_ipv4() {
                return Err(SrtError::InvalidParam);
            }
        }
        if self.weight > MAX_GROUP_MEMBER_WEIGHT || self.token < 0 {
            return Err(SrtError::InvalidParam);
        }
        Ok(())
    }
}

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
    /// libsrt's member weight (backup mode): the **greater** weight is
    /// preferred, `0..=`[`MAX_GROUP_MEMBER_WEIGHT`]; all-equal means libsrt
    /// picks. On a caller group it is what [`GroupEndpoint::weight`] set; on a
    /// listener's mirror group it is what the remote caller sent in the group
    /// handshake.
    pub weight: u16,
    /// The [`GroupEndpoint::token`] the member was created with (caller
    /// groups); libsrt-generated on a listener's mirror group. Matches a
    /// member back to its endpoint, which `peer_addr` cannot do reliably.
    pub token: i32,
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

    /// Connect one more member into this live group — typically to bring
    /// back a member libsrt removed as broken, with the same
    /// [`GroupEndpoint`] (source, weight, token) it was first created with.
    ///
    /// Returns once the member is spawned; its handshake completes in the
    /// background and shows up on [`SrtGroup::member_stats`] (`Pending`, then
    /// `Idle`/`Running`, or gone if it fails). The member inherits the
    /// group's options and joins at the group's current sequence number.
    ///
    /// **Refused (`ConnectionLost`) unless at least one member is Idle or
    /// Running**, checked on the I/O thread immediately before the connect.
    /// libsrt counts a *pending* member as healthy when deciding whether the
    /// group has failed, so a member added to a group with no live link
    /// would keep a dead group in `Connecting` — its sends stalled — instead
    /// of letting it break and be redialled whole. Also refused once the
    /// group has been closed or the bridge has seen it break.
    ///
    /// A bind failure on `local_addr` is reported as itself, not as a
    /// generic connection loss.
    pub async fn add_member(&self, ep: GroupEndpoint) -> Result<(), SrtError> {
        ep.check()?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.io.send_command(IoCommand::AddGroupMember {
            id: self.id,
            endpoint: ep,
            reply: reply_tx,
        });
        reply_rx.await.map_err(|_| SrtError::SocketFail)?
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
    endpoints: Vec<GroupEndpoint>,
}

impl SrtGroupBuilder {
    pub fn new(mode: GroupMode) -> Self {
        Self {
            mode,
            config: SrtConfig::default(),
            endpoints: Vec::new(),
        }
    }

    /// Add an endpoint to the group: unbound, weight 0, with its index in
    /// the builder as its token. Use [`SrtGroupBuilder::add_member`] to set a
    /// source address, a weight or a token of your own — mixing the two
    /// can give two members the same token.
    pub fn add_endpoint(mut self, addr: SocketAddr) -> Self {
        let token = self.endpoints.len() as i32;
        self.endpoints.push(GroupEndpoint::new(addr, token));
        self
    }

    /// Add a fully specified member. See [`GroupEndpoint`].
    pub fn add_member(mut self, ep: GroupEndpoint) -> Self {
        self.endpoints.push(ep);
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
    ///
    /// Every endpoint is [checked](GroupEndpoint::check) first: libsrt
    /// refuses the whole call for one bad member, so a bad one is reported
    /// here, before any group exists. When libsrt spawns no member (each
    /// one refused, e.g. a `local_addr` this host cannot bind), the group
    /// already created is closed before the error is returned.
    pub async fn connect(self) -> Result<Arc<SrtGroup>, SrtError> {
        if self.endpoints.is_empty() {
            return Err(SrtError::InvalidParam);
        }
        for ep in &self.endpoints {
            ep.check()?;
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
        if let Err(e) = conn_rx.await.map_err(|_| SrtError::SocketFail).and_then(|r| r) {
            // libsrt keeps a group whose `srt_connect_group` spawned no
            // member, and nothing else would ever close this one: no
            // `SrtGroup` owns it yet, and the bridge's zombie sweep skips
            // groups. Left open, every failed connect kept a libsrt group
            // (two kernel epoll fds) and its bridge entry for good, so a
            // caller retrying members whose sources this host cannot bind
            // leaked them on every attempt.
            io.send_command(IoCommand::Close { id });
            return Err(e);
        }

        Ok(Arc::new(SrtGroup {
            id,
            io,
            send_tx,
            recv_rx: tokio::sync::Mutex::new(recv_rx),
            status_rx,
            mode: self.mode,
            endpoints: self.endpoints.iter().map(|ep| ep.addr).collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// libsrt throws `MN_INVAL` for the whole `srt_connect_group` call when a
    /// member's source family differs from its target's.
    #[test]
    fn group_endpoint_check_refuses_a_family_mismatch() {
        let mut ep = GroupEndpoint::new(v4("[2001:db8::1]:9000"), 0);
        ep.local_addr = Some(v4("192.0.2.1:0"));
        assert_eq!(ep.check(), Err(SrtError::InvalidParam));
        ep.local_addr = Some(v4("[::]:0"));
        assert_eq!(ep.check(), Ok(()));
    }

    /// `CUDT::MAX_WEIGHT` is 32767; one above it fails the whole group call.
    #[test]
    fn group_endpoint_check_refuses_weight_above_libsrt_max() {
        let mut ep = GroupEndpoint::new(v4("127.0.0.1:9000"), 0);
        ep.weight = MAX_GROUP_MEMBER_WEIGHT;
        assert_eq!(ep.check(), Ok(()));
        ep.weight = MAX_GROUP_MEMBER_WEIGHT + 1;
        assert_eq!(ep.check(), Err(SrtError::InvalidParam));
    }

    /// A negative token would be replaced by a libsrt-generated one, and the
    /// member could no longer be matched to its endpoint.
    #[test]
    fn group_endpoint_check_refuses_a_negative_token() {
        assert_eq!(
            GroupEndpoint::new(v4("127.0.0.1:9000"), -1).check(),
            Err(SrtError::InvalidParam)
        );
    }

    /// The legacy `add_endpoint(SocketAddr)` keeps producing today's libsrt
    /// call — no source, weight 0 — and now names each member by its index.
    #[test]
    fn add_endpoint_is_unbound_weight_zero_with_index_tokens() {
        let b = SrtGroup::builder(GroupMode::Broadcast)
            .add_endpoint(v4("127.0.0.1:9000"))
            .add_endpoint(v4("127.0.0.1:9001"));
        assert_eq!(
            b.endpoints,
            vec![
                GroupEndpoint::new(v4("127.0.0.1:9000"), 0),
                GroupEndpoint::new(v4("127.0.0.1:9001"), 1),
            ]
        );
        assert!(b.endpoints.iter().all(|ep| ep.local_addr.is_none() && ep.weight == 0));
    }

    /// A bad member is refused before any group is created: `connect`
    /// returns `InvalidParam` without a round trip to the I/O thread.
    #[test]
    fn builder_refuses_bad_endpoint_before_touching_libsrt() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut bad = GroupEndpoint::new(v4("127.0.0.1:9001"), 1);
        bad.weight = MAX_GROUP_MEMBER_WEIGHT + 1;
        let result = rt.block_on(
            SrtGroup::builder(GroupMode::Backup)
                .add_endpoint(v4("127.0.0.1:9000"))
                .add_member(bad)
                .connect(),
        );
        assert_eq!(result.err(), Some(SrtError::InvalidParam));
    }
}
