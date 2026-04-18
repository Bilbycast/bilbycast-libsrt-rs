// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT performance statistics.
//!
//! [`SrtStats`] contains 80+ counters for monitoring connection health,
//! throughput, and quality. Maps to the C `CBytePerfMon` / `SRT_TRACEBSTATS`.

/// Performance statistics for an SRT connection.
///
/// Maps to the C `CBytePerfMon` / `SRT_TRACEBSTATS` structure.
/// Counters are split into "total" (cumulative from connection start)
/// and "local" (since last stats reset).
#[derive(Debug, Clone, Default)]
pub struct SrtStats {
    // ── Global (total) measurements ──

    /// Time since the SRT entity started, in milliseconds.
    pub ms_timestamp: i64,
    /// Total sent data packets (including retransmissions).
    pub pkt_sent_total: i64,
    /// Total received packets.
    pub pkt_recv_total: i64,
    /// Total lost packets (sender side).
    pub pkt_snd_loss_total: i32,
    /// Total lost packets (receiver side).
    pub pkt_rcv_loss_total: i32,
    /// Total retransmitted packets.
    pub pkt_retrans_total: i32,
    /// Total sent ACK packets.
    pub pkt_sent_ack_total: i32,
    /// Total received ACK packets.
    pub pkt_recv_ack_total: i32,
    /// Total sent NAK packets.
    pub pkt_sent_nak_total: i32,
    /// Total received NAK packets.
    pub pkt_recv_nak_total: i32,
    /// Total sending duration (microseconds, idle time excluded).
    pub us_snd_duration_total: i64,
    /// Total too-late-to-send dropped packets.
    pub pkt_snd_drop_total: i32,
    /// Total too-late-to-play missing packets.
    pub pkt_rcv_drop_total: i32,
    /// Total undecrypted packets.
    pub pkt_rcv_undecrypt_total: i32,
    /// Total sent bytes (including retransmissions).
    pub byte_sent_total: u64,
    /// Total received bytes.
    pub byte_recv_total: u64,
    /// Total lost bytes (receiver side).
    pub byte_rcv_loss_total: u64,
    /// Total retransmitted bytes.
    pub byte_retrans_total: u64,
    /// Total too-late-to-send dropped bytes.
    pub byte_snd_drop_total: u64,
    /// Total too-late-to-play dropped bytes.
    pub byte_rcv_drop_total: u64,
    /// Total undecrypted bytes.
    pub byte_rcv_undecrypt_total: u64,
    /// Total unique sent data packets.
    pub pkt_sent_unique_total: i64,
    /// Total unique received data packets.
    pub pkt_recv_unique_total: i64,
    /// Total unique sent data bytes.
    pub byte_sent_unique_total: u64,
    /// Total unique received data bytes.
    pub byte_recv_unique_total: u64,

    // ── Local (since last reset) measurements ──

    /// Sent data packets (including retransmissions).
    pub pkt_sent: i64,
    /// Received packets.
    pub pkt_recv: i64,
    /// Lost packets (sender side).
    pub pkt_snd_loss: i32,
    /// Lost packets (receiver side).
    pub pkt_rcv_loss: i32,
    /// Retransmitted packets.
    pub pkt_retrans: i32,
    /// Retransmitted packets received (instant, reset on snapshot).
    pub pkt_rcv_retrans: i32,
    /// Retransmitted packets received (cumulative).
    pub pkt_rcv_retrans_total: i32,
    /// Sent ACK packets.
    pub pkt_sent_ack: i32,
    /// Received ACK packets.
    pub pkt_recv_ack: i32,
    /// Sent NAK packets.
    pub pkt_sent_nak: i32,
    /// Received NAK packets.
    pub pkt_recv_nak: i32,
    /// Sending rate in Mb/s.
    pub mbps_send_rate: f64,
    /// Receiving rate in Mb/s.
    pub mbps_recv_rate: f64,
    /// Busy sending duration (microseconds, idle excluded).
    pub us_snd_duration: i64,
    /// Reorder distance in received sequences.
    pub pkt_reorder_distance: i32,
    /// Average delay for belated packets.
    pub pkt_rcv_avg_belated_time: f64,
    /// Received and ignored belated packets.
    pub pkt_rcv_belated: i64,
    /// Too-late-to-send dropped packets.
    pub pkt_snd_drop: i32,
    /// Too-late-to-play dropped packets.
    pub pkt_rcv_drop: i32,
    /// Undecrypted packets.
    pub pkt_rcv_undecrypt: i32,
    /// Sent bytes (including retransmissions).
    pub byte_sent: u64,
    /// Received bytes.
    pub byte_recv: u64,
    /// Lost bytes (receiver side).
    pub byte_rcv_loss: u64,
    /// Retransmitted bytes.
    pub byte_retrans: u64,
    /// Too-late-to-send dropped bytes.
    pub byte_snd_drop: u64,
    /// Too-late-to-play dropped bytes.
    pub byte_rcv_drop: u64,
    /// Undecrypted bytes.
    pub byte_rcv_undecrypt: u64,
    /// Unique sent data packets.
    pub pkt_sent_unique: i64,
    /// Unique received data packets.
    pub pkt_recv_unique: i64,
    /// Unique sent data bytes.
    pub byte_sent_unique: u64,
    /// Unique received data bytes.
    pub byte_recv_unique: u64,

    // ── Instant measurements ──

    /// Packet sending period in microseconds.
    pub us_pkt_snd_period: f64,
    /// Flow window size in packets.
    pub pkt_flow_window: i32,
    /// Congestion window size in packets.
    pub pkt_congestion_window: i32,
    /// Number of packets in flight.
    pub pkt_flight_size: i32,
    /// RTT in milliseconds.
    pub ms_rtt: f64,
    /// Estimated bandwidth in Mb/s.
    pub mbps_bandwidth: f64,
    /// Available sender buffer size in bytes.
    pub byte_avail_snd_buf: i32,
    /// Available receiver buffer size in bytes.
    pub byte_avail_rcv_buf: i32,
    /// Transmit bandwidth ceiling in Mb/s.
    pub mbps_max_bw: f64,
    /// MTU size.
    pub byte_mss: i32,

    /// Unacknowledged packets in sender buffer.
    pub pkt_snd_buf: i32,
    /// Unacknowledged bytes in sender buffer.
    pub byte_snd_buf: i32,
    /// Unacknowledged timespan in sender buffer (ms).
    pub ms_snd_buf: i32,
    /// Sender TSBPD delay (ms).
    pub ms_snd_tsbpd_delay: i32,

    /// Undelivered packets in receiver buffer.
    pub pkt_rcv_buf: i32,
    /// Undelivered bytes in receiver buffer.
    pub byte_rcv_buf: i32,
    /// Undelivered timespan in receiver buffer (ms).
    pub ms_rcv_buf: i32,
    /// Receiver TSBPD delay (ms).
    pub ms_rcv_tsbpd_delay: i32,

    // ── Filter statistics ──

    /// Filter control packets supplied (total).
    pub pkt_snd_filter_extra_total: i32,
    /// Filter control packets received (total).
    pub pkt_rcv_filter_extra_total: i32,
    /// Filter rebuilt packets (total).
    pub pkt_rcv_filter_supply_total: i32,
    /// Filter uncoverable losses (total).
    pub pkt_rcv_filter_loss_total: i32,

    /// Filter control packets supplied (local).
    pub pkt_snd_filter_extra: i32,
    /// Filter control packets received (local).
    pub pkt_rcv_filter_extra: i32,
    /// Filter rebuilt packets (local).
    pub pkt_rcv_filter_supply: i32,
    /// Filter uncoverable losses (local).
    pub pkt_rcv_filter_loss: i32,
    /// Packet reorder tolerance.
    pub pkt_reorder_tolerance: i32,
}

impl SrtStats {
    /// Reset the local (interval) counters.
    pub fn reset_local(&mut self) {
        self.pkt_sent = 0;
        self.pkt_recv = 0;
        self.pkt_snd_loss = 0;
        self.pkt_rcv_loss = 0;
        self.pkt_retrans = 0;
        self.pkt_rcv_retrans = 0;
        self.pkt_sent_ack = 0;
        self.pkt_recv_ack = 0;
        self.pkt_sent_nak = 0;
        self.pkt_recv_nak = 0;
        self.mbps_send_rate = 0.0;
        self.mbps_recv_rate = 0.0;
        self.us_snd_duration = 0;
        self.pkt_reorder_distance = 0;
        self.pkt_rcv_avg_belated_time = 0.0;
        self.pkt_rcv_belated = 0;
        self.pkt_snd_drop = 0;
        self.pkt_rcv_drop = 0;
        self.pkt_rcv_undecrypt = 0;
        self.byte_sent = 0;
        self.byte_recv = 0;
        self.byte_rcv_loss = 0;
        self.byte_retrans = 0;
        self.byte_snd_drop = 0;
        self.byte_rcv_drop = 0;
        self.byte_rcv_undecrypt = 0;
        self.pkt_sent_unique = 0;
        self.pkt_recv_unique = 0;
        self.byte_sent_unique = 0;
        self.byte_recv_unique = 0;
        self.pkt_snd_filter_extra = 0;
        self.pkt_rcv_filter_extra = 0;
        self.pkt_rcv_filter_supply = 0;
        self.pkt_rcv_filter_loss = 0;
    }
}
