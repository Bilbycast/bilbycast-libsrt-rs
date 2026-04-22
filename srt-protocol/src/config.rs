// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT socket configuration and options.
//!
//! [`SrtConfig`] holds all configurable parameters for an SRT connection,
//! including latency, buffer sizes, encryption settings, and transport mode.
//! Maps to the C `CSrtConfig` / `CSrtMuxerConfig` structures.

use std::time::Duration;

/// SRT transmission mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransType {
    /// Live streaming mode: low latency, TSBPD, packet dropping.
    Live,
    /// File transfer mode: reliable delivery, AIMD congestion control.
    File,
}

impl Default for TransType {
    fn default() -> Self {
        Self::Live
    }
}

/// Encryption cipher mode selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CryptoModeConfig {
    /// AES Counter mode (default, compatible with all SRT implementations).
    #[default]
    AesCtr,
    /// AES Galois/Counter mode — authenticated encryption. Requires libsrt >= 1.5.2
    /// on the peer. Only supports AES-128 and AES-256 (not AES-192).
    AesGcm,
}

/// Encryption key length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeySize {
    AES128 = 16,
    AES192 = 24,
    AES256 = 32,
}

impl KeySize {
    pub fn from_bytes(len: usize) -> Option<Self> {
        match len {
            16 => Some(Self::AES128),
            24 => Some(Self::AES192),
            32 => Some(Self::AES256),
            _ => None,
        }
    }

    /// Encode key size into the KM Klen/4 field (key_size_bytes / 4).
    pub fn to_km_field(self) -> u32 {
        (self as u32) / 4
    }

    /// Decode from the KM Klen/4 field (value * 4 -> key_size_bytes).
    pub fn from_km_field(field: u32) -> Option<Self> {
        Self::from_bytes((field * 4) as usize)
    }
}

/// Retransmission algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetransmitAlgo {
    /// Default retransmission algorithm.
    Default = 0,
    /// Reduced retransmission (avoid unnecessary retransmissions).
    Reduced = 1,
}

/// Key material state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KmState {
    Unsecured = 0,
    Securing = 1,
    Secured = 2,
    NoSecret = 3,
    BadSecret = 4,
    BadCryptoMode = 5,
}

impl KmState {
    pub fn from_value(v: i32) -> Self {
        match v {
            0 => Self::Unsecured,
            1 => Self::Securing,
            2 => Self::Secured,
            3 => Self::NoSecret,
            4 => Self::BadSecret,
            5 => Self::BadCryptoMode,
            _ => Self::Unsecured,
        }
    }
}

/// SRT socket configuration.
///
/// Maps to C `CSrtConfig` / `SRT_SOCKOPT`. This struct drives
/// `SRTO_*` socket option calls in the transport layer.
#[derive(Debug, Clone)]
pub struct SrtConfig {
    // ── Transport ──
    pub mss: u32,
    pub flight_flag_size: u32,
    pub send_buffer_size: u32,
    pub recv_buffer_size: u32,
    pub udp_send_buffer_size: u32,
    pub udp_recv_buffer_size: u32,
    pub send_sync: bool,
    pub recv_sync: bool,
    pub send_timeout: Option<Duration>,
    pub recv_timeout: Option<Duration>,
    pub reuse_addr: bool,
    pub linger: Option<Duration>,

    // ── Connection ──
    pub connect_timeout: Duration,
    pub rendezvous: bool,
    pub ipv6_only: bool,
    pub ip_ttl: i32,
    pub ip_tos: i32,
    pub bind_to_device: Option<String>,
    pub peer_idle_timeout: Duration,

    // ── Transmission ──
    pub trans_type: TransType,
    pub message_api: bool,
    pub payload_size: u32,
    pub max_bw: i64,
    pub input_bw: i64,
    pub min_input_bw: i64,
    pub overhead_bw: i32,
    pub max_rexmit_bw: i64,

    // ── Live mode ──
    pub tsbpd_mode: bool,
    pub recv_latency: u32,
    pub peer_latency: u32,
    pub tlpkt_drop: bool,
    pub send_drop_delay: i32,
    pub nak_report: bool,
    pub drift_tracer: bool,
    pub loss_max_ttl: i32,

    // ── Encryption ──
    pub passphrase: String,
    pub key_size: KeySize,
    pub crypto_mode: CryptoModeConfig,
    pub enforced_encryption: bool,
    pub km_refresh_rate: u32,
    pub km_pre_announce: u32,

    // ── Sender flag ──
    pub sender: bool,

    // ── Stream ID ──
    pub stream_id: String,

    // ── Congestion ──
    pub congestion: String,

    // ── Packet filter ──
    pub packet_filter: String,

    // ── Retransmission ──
    pub retransmit_algo: RetransmitAlgo,

    // ── Minimum peer version ──
    pub min_version: u32,

    // ── Bonding ──
    pub group_connect: bool,
    pub group_min_stable_timeout: Duration,
}

impl Default for SrtConfig {
    fn default() -> Self {
        Self {
            mss: 1500,
            flight_flag_size: 25600,
            send_buffer_size: 8192 * 1316,
            recv_buffer_size: 8192 * 1316,
            udp_send_buffer_size: 65536,
            udp_recv_buffer_size: 65536,
            send_sync: true,
            recv_sync: true,
            send_timeout: None,
            recv_timeout: None,
            reuse_addr: true,
            linger: Some(Duration::from_secs(180)),

            connect_timeout: Duration::from_secs(3),
            rendezvous: false,
            ipv6_only: false,
            ip_ttl: 64,
            ip_tos: 0,
            bind_to_device: None,
            peer_idle_timeout: Duration::from_secs(5),

            trans_type: TransType::Live,
            message_api: true,
            payload_size: 1316,
            // max_bw = -1 (unlimited) not 0 (libsrt "Live"-default "relative to
            // input_bw"). The Live default relies on libsrt's internal input-bw
            // estimator, which is conservative for the first ~1 s and causes
            // the send buffer to drop packets (past SNDDROPDELAY) when a
            // bursty upstream (ffmpeg -re, camera initial buffer) exceeds it.
            // Correlates across legs under 2022-7 so the merger can't hide it,
            // and blows past the FEC matrix when FEC is layered on top,
            // triggering libsrt's SRT.pf `FEC: IPE` path. Defaulting unlimited
            // matches the File-transtype default and the role of this crate:
            // a forwarding gateway, where upstream pacing is already correct
            // and libsrt should not second-guess it. Operators can still set
            // an explicit `max_bw` / `input_bw` if they need per-link caps.
            max_bw: -1,
            input_bw: 0,
            min_input_bw: 0,
            overhead_bw: 25,
            max_rexmit_bw: -1,

            tsbpd_mode: true,
            recv_latency: 120,
            peer_latency: 0,
            tlpkt_drop: true,
            send_drop_delay: -1,
            nak_report: true,
            drift_tracer: true,
            loss_max_ttl: 0,

            passphrase: String::new(),
            key_size: KeySize::AES128,
            crypto_mode: CryptoModeConfig::default(),
            enforced_encryption: true,
            km_refresh_rate: 0x0100_0000,
            km_pre_announce: 0x1000,

            sender: false,
            stream_id: String::new(),
            congestion: String::from("live"),
            packet_filter: String::new(),
            retransmit_algo: RetransmitAlgo::Default,
            min_version: 0,

            group_connect: false,
            group_min_stable_timeout: Duration::from_millis(60),
        }
    }
}

impl SrtConfig {
    /// Apply `SRTT_LIVE` transmission type defaults.
    pub fn live_defaults(&mut self) {
        self.trans_type = TransType::Live;
        self.message_api = true;
        self.tsbpd_mode = true;
        self.tlpkt_drop = true;
        self.nak_report = true;
        self.payload_size = 1316;
        self.congestion = String::from("live");
    }

    /// Apply `SRTT_FILE` transmission type defaults.
    pub fn file_defaults(&mut self) {
        self.trans_type = TransType::File;
        self.message_api = true;
        self.tsbpd_mode = false;
        self.tlpkt_drop = false;
        self.nak_report = false;
        self.payload_size = 0;
        self.congestion = String::from("file");
    }

    /// Whether encryption is enabled.
    pub fn encryption_enabled(&self) -> bool {
        !self.passphrase.is_empty()
    }
}

/// SRT socket status (state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketStatus {
    Init = 1,
    Opened = 2,
    Listening = 3,
    Connecting = 4,
    Connected = 5,
    Broken = 6,
    Closing = 7,
    Closed = 8,
    NonExist = 9,
}

/// Per-member status inside an SRT socket group (bonding).
///
/// Mirrors libsrt's `SRT_MEMBERSTATUS`. Surfaced via
/// `SrtGroup::member_stats()` on the transport crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemberStatus {
    /// Member is still negotiating the connection.
    Pending,
    /// Member is connected but not currently carrying traffic (standby backup).
    Idle,
    /// Member is actively carrying traffic.
    Running,
    /// Member connection is broken / dead.
    Broken,
}

/// Default SRT live payload size (MPEG-TS: 188 * 7).
pub const SRT_LIVE_DEF_PLSIZE: u32 = 1316;

/// Maximum payload for live mode.
pub const SRT_LIVE_MAX_PLSIZE: u32 = 1456;

/// Default live latency in milliseconds.
pub const SRT_LIVE_DEF_LATENCY_MS: u32 = 120;
