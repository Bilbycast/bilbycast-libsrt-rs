// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! A bonded caller group (`SrtGroup`) carries media, end to end, against a
//! group listener.
//!
//! # Why this exists
//!
//! Nothing ever proved it did, and it did not: libsrt raises ERR readiness
//! on a group whose members are all still connecting when the group is added
//! to an epoll, and the bridge adds it at exactly that moment. Every caller
//! group was marked `Broken` at birth — its sends and receives failed with
//! `ConnectionLost` before a member had finished its handshake — and a
//! memberless group's `SRTS_BROKEN` at `RegisterSocket` had already dropped
//! its receive channel. Both cases below fail on the code before that fix.
//!
//! # Why `harness = false`
//!
//! Same reason as `listener_access_control.rs`, whose module docs carry the
//! detail: these open real SRT sockets, and the process must leave with
//! `libc::_exit(0)` before libsrt's C++ statics are torn down.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use srt_transport::{GroupMode, SocketStatus, SrtGroup, SrtListener};

/// Generous: libsrt's own timers (connect timeout 3 s, the bridge's ~1 s
/// state poll) decide how fast things move, and a loaded host should not
/// turn a slow pass into a failure.
const DEADLINE: Duration = Duration::from_secs(10);

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let mut passed = 0;

    rt.block_on(a_caller_group_survives_its_own_connect_and_carries_media_both_ways());
    println!("test a_caller_group_survives_its_own_connect_and_carries_media_both_ways ... ok");
    passed += 1;

    println!("\ntest result: ok. {passed} passed; 0 failed");
    let _ = std::io::stdout().flush();

    // Leave before the C++ static destructors run. See the module docs.
    unsafe { libc::_exit(0) };
}

// ── Rig ─────────────────────────────────────────────────────────────────

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

async fn group_listener() -> SrtListener {
    SrtListener::builder()
        .live_mode()
        .latency(Duration::from_millis(120))
        .group_connect(true)
        .bind(addr("127.0.0.1:0"))
        .await
        .expect("group listener bind")
}

fn terminal(s: SocketStatus) -> bool {
    matches!(
        s,
        SocketStatus::Broken | SocketStatus::Closing | SocketStatus::Closed | SocketStatus::NonExist
    )
}

fn message(seq: u32) -> Vec<u8> {
    let mut msg = vec![(seq as u8) ^ 0x5a; 1200];
    msg[..4].copy_from_slice(&seq.to_be_bytes());
    msg
}

const MESSAGES: u32 = 20;

// ── Cases ───────────────────────────────────────────────────────────────

/// A two-member broadcast caller group stays up past the moment the bridge
/// registers it, and every message crosses in both directions.
async fn a_caller_group_survives_its_own_connect_and_carries_media_both_ways() {
    let mut listener = group_listener().await;
    let target = listener.local_addr();
    let group: Arc<SrtGroup> = SrtGroup::builder(GroupMode::Broadcast)
        .live_mode()
        .latency(Duration::from_millis(120))
        .connect_timeout(Duration::from_secs(3))
        .add_endpoint(target)
        .add_endpoint(target)
        .connect()
        .await
        .expect("group connect");
    let accepted = tokio::time::timeout(DEADLINE, listener.accept())
        .await
        .expect("listener never accepted the group")
        .expect("accept");

    // Past the bridge's first ~1 s state poll as well as the epoll add.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!terminal(group.status()), "caller group torn down at birth: {:?}", group.status());

    // Caller -> listener.
    for seq in 0..MESSAGES {
        group.send(&message(seq)).await.expect("caller group send");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for seq in 0..MESSAGES {
        let pkt = tokio::time::timeout(DEADLINE, accepted.recv())
            .await
            .unwrap_or_else(|_| panic!("listener: message {seq} never arrived"))
            .expect("listener recv");
        assert_eq!(pkt.data.as_ref(), message(seq).as_slice(), "listener: message {seq}");
    }

    // Listener -> caller.
    for seq in 0..MESSAGES {
        accepted.send(&message(seq)).await.expect("listener send");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for seq in 0..MESSAGES {
        let pkt = tokio::time::timeout(DEADLINE, group.recv())
            .await
            .unwrap_or_else(|_| panic!("caller group: message {seq} never arrived"))
            .expect("caller group recv");
        assert_eq!(pkt.data.as_ref(), message(seq).as_slice(), "caller group: message {seq}");
    }
    assert!(!terminal(group.status()), "caller group status: {:?}", group.status());

    let _ = group.close().await;
    let _ = accepted.close().await;
    let _ = listener.close().await;
}
