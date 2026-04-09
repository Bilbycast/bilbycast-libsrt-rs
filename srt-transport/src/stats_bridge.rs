// Copyright (c) 2026 Reza Rahimi / Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Convert libsrt's `CBytePerfMon` to the Rust `SrtStats` struct.

use libsrt_sys::CBytePerfMon;
use srt_protocol::stats::SrtStats;

/// Convert a libsrt `CBytePerfMon` (aka `SRT_TRACEBSTATS`) into our `SrtStats`.
///
/// This is a direct 1:1 field mapping — the `SrtStats` struct was designed
/// to match `CBytePerfMon`.
pub(crate) fn convert_perfmon_to_stats(perf: &CBytePerfMon) -> SrtStats {
    SrtStats {
        // Global (total) measurements
        ms_timestamp: perf.msTimeStamp,
        pkt_sent_total: perf.pktSentTotal,
        pkt_recv_total: perf.pktRecvTotal,
        pkt_snd_loss_total: perf.pktSndLossTotal,
        pkt_rcv_loss_total: perf.pktRcvLossTotal,
        pkt_retrans_total: perf.pktRetransTotal,
        pkt_sent_ack_total: perf.pktSentACKTotal,
        pkt_recv_ack_total: perf.pktRecvACKTotal,
        pkt_sent_nak_total: perf.pktSentNAKTotal,
        pkt_recv_nak_total: perf.pktRecvNAKTotal,
        us_snd_duration_total: perf.usSndDurationTotal,
        pkt_snd_drop_total: perf.pktSndDropTotal,
        pkt_rcv_drop_total: perf.pktRcvDropTotal,
        pkt_rcv_undecrypt_total: perf.pktRcvUndecryptTotal,
        byte_sent_total: perf.byteSentTotal,
        byte_recv_total: perf.byteRecvTotal,
        byte_rcv_loss_total: perf.byteRcvLossTotal,
        byte_retrans_total: perf.byteRetransTotal,
        byte_snd_drop_total: perf.byteSndDropTotal,
        byte_rcv_drop_total: perf.byteRcvDropTotal,
        byte_rcv_undecrypt_total: perf.byteRcvUndecryptTotal,
        pkt_sent_unique_total: perf.pktSentUniqueTotal,
        pkt_recv_unique_total: perf.pktRecvUniqueTotal,
        byte_sent_unique_total: perf.byteSentUniqueTotal,
        byte_recv_unique_total: perf.byteRecvUniqueTotal,

        // Local (since last reset) measurements
        pkt_sent: perf.pktSent,
        pkt_recv: perf.pktRecv,
        pkt_snd_loss: perf.pktSndLoss,
        pkt_rcv_loss: perf.pktRcvLoss,
        pkt_retrans: perf.pktRetrans,
        pkt_rcv_retrans: perf.pktRcvRetrans,
        pkt_rcv_retrans_total: 0, // Not available in libsrt's CBytePerfMon
        pkt_sent_ack: perf.pktSentACK,
        pkt_recv_ack: perf.pktRecvACK,
        pkt_sent_nak: perf.pktSentNAK,
        pkt_recv_nak: perf.pktRecvNAK,
        mbps_send_rate: perf.mbpsSendRate,
        mbps_recv_rate: perf.mbpsRecvRate,
        us_snd_duration: perf.usSndDuration,
        pkt_reorder_distance: perf.pktReorderDistance,
        pkt_rcv_avg_belated_time: perf.pktRcvAvgBelatedTime,
        pkt_rcv_belated: perf.pktRcvBelated,
        pkt_snd_drop: perf.pktSndDrop,
        pkt_rcv_drop: perf.pktRcvDrop,
        pkt_rcv_undecrypt: perf.pktRcvUndecrypt,
        byte_sent: perf.byteSent,
        byte_recv: perf.byteRecv,
        byte_rcv_loss: perf.byteRcvLoss,
        byte_retrans: perf.byteRetrans,
        byte_snd_drop: perf.byteSndDrop,
        byte_rcv_drop: perf.byteRcvDrop,
        byte_rcv_undecrypt: perf.byteRcvUndecrypt,
        pkt_sent_unique: perf.pktSentUnique,
        pkt_recv_unique: perf.pktRecvUnique,
        byte_sent_unique: perf.byteSentUnique,
        byte_recv_unique: perf.byteRecvUnique,

        // Instant measurements
        us_pkt_snd_period: perf.usPktSndPeriod,
        pkt_flow_window: perf.pktFlowWindow,
        pkt_congestion_window: perf.pktCongestionWindow as i32,
        pkt_flight_size: perf.pktFlightSize,
        ms_rtt: perf.msRTT,
        mbps_bandwidth: perf.mbpsBandwidth,
        byte_avail_snd_buf: perf.byteAvailSndBuf,
        byte_avail_rcv_buf: perf.byteAvailRcvBuf,
        mbps_max_bw: perf.mbpsMaxBW,
        byte_mss: perf.byteMSS,

        pkt_snd_buf: perf.pktSndBuf,
        byte_snd_buf: perf.byteSndBuf,
        ms_snd_buf: perf.msSndBuf,
        ms_snd_tsbpd_delay: perf.msSndTsbPdDelay,

        pkt_rcv_buf: perf.pktRcvBuf,
        byte_rcv_buf: perf.byteRcvBuf,
        ms_rcv_buf: perf.msRcvBuf,
        ms_rcv_tsbpd_delay: perf.msRcvTsbPdDelay,

        // Filter statistics
        pkt_snd_filter_extra_total: perf.pktSndFilterExtraTotal,
        pkt_rcv_filter_extra_total: perf.pktRcvFilterExtraTotal,
        pkt_rcv_filter_supply_total: perf.pktRcvFilterSupplyTotal,
        pkt_rcv_filter_loss_total: perf.pktRcvFilterLossTotal,

        pkt_snd_filter_extra: perf.pktSndFilterExtra,
        pkt_rcv_filter_extra: perf.pktRcvFilterExtra,
        pkt_rcv_filter_supply: perf.pktRcvFilterSupply,
        pkt_rcv_filter_loss: perf.pktRcvFilterLoss,
        pkt_reorder_tolerance: perf.pktReorderTolerance,
    }
}
