// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Receive-side packet container with sender metadata.
//!
//! Returned from [`SrtSocket::recv`] and friends. Carries the payload
//! bytes alongside the per-packet metadata libsrt surfaces via
//! `SRT_MsgCtrl` — most importantly `srctime`, the sender-set
//! microsecond timestamp that bilbycast's master-clock uses for rate
//! recovery on internet-contribution paths where MPEG-TS PCR sampled
//! from the bytes after a 200 ms+ latency-buffer release is too
//! bursty for the PLL to lock cleanly.
//!
//! ## API surface choice
//!
//! Bundled metadata (this struct), not a parallel `recv_with_meta()`
//! method. Matches the industry pattern — librist's `RistDataBlock`,
//! GStreamer's `GstSample`, FFmpeg's `AVPacket`, libsrt's own C
//! `srt_recvmsg2` — every serious media-transport library returns
//! payload + metadata as one unit. Callers that don't need the
//! metadata pay nothing extra (a single `Option<i64>` in the struct).
//!
//! ## API parity
//!
//! Mirrored byte-for-byte in `bilbycast-srt/srt-protocol/src/received_packet.rs`
//! so the two backends remain drop-in swappable per
//! `bilbycast-edge/Cargo.toml`'s `── SRT backend ──` block. Changes
//! here must land in both backends.

use bytes::Bytes;

/// One application-layer packet delivered by SRT, with the sender's
/// per-packet metadata when available.
#[derive(Debug, Clone)]
pub struct ReceivedPacket {
    /// Application payload (post-decryption, post-FEC-recover,
    /// post-loss-recovery — exactly what the sender's `srt_sendmsg`
    /// passed in).
    pub data: Bytes,
    /// Sender-set delivery timestamp from libsrt's
    /// `SRT_MsgCtrl::srctime`, in microseconds since the Unix epoch.
    ///
    /// `None` when:
    /// - The sender's send-side msgctrl was NULL and libsrt used
    ///   internal time without propagating it (rare on libsrt 1.5.x
    ///   but possible across multi-hop forwarders).
    /// - The receive path didn't request a msgctrl (e.g. callers using
    ///   the legacy `recv()` shape that returns `Bytes` directly —
    ///   preserved by the wrapper functions for backwards-compat).
    ///
    /// **Use for**: feeding bilbycast-edge's `SenderTimestampMaster`
    /// as the PLL rate reference. Cleaner than MPEG-TS PCR sampled
    /// from the bytes because the timestamp is set at the sender's
    /// `sendmsg()` — pre-network-jitter — and is not subject to the
    /// bursty arrival cadence that PCR-from-bytes sees behind the
    /// TSBPD latency buffer.
    ///
    /// **Don't use for**: wallclock synchronisation across edges.
    /// libsrt's srctime is the sender's monotonic-ish wallclock, not
    /// a shared PTP-disciplined timebase.
    pub sender_timestamp_us: Option<i64>,
}

impl ReceivedPacket {
    /// Build with no sender timestamp (legacy callers, raw-recv path).
    pub fn from_bytes(data: Bytes) -> Self {
        Self {
            data,
            sender_timestamp_us: None,
        }
    }

    /// Build with the sender's microsecond timestamp.
    pub fn with_srctime(data: Bytes, srctime_us: i64) -> Self {
        // Treat 0 as "absent" — libsrt's documented sentinel for
        // "sender did not set srctime, fall back to internal time".
        // Consumers expecting genuine timestamps should not see 0s
        // leak into the PLL feed.
        let ts = if srctime_us == 0 { None } else { Some(srctime_us) };
        Self {
            data,
            sender_timestamp_us: ts,
        }
    }

    /// Discard metadata, return payload bytes. Legacy-API convenience.
    #[inline]
    pub fn into_bytes(self) -> Bytes {
        self.data
    }
}

impl From<Bytes> for ReceivedPacket {
    fn from(data: Bytes) -> Self {
        Self::from_bytes(data)
    }
}

impl AsRef<[u8]> for ReceivedPacket {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}
