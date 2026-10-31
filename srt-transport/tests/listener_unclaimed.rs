// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! A connection the listener accepted but nobody took is closed, never left
//! open.
//!
//! The I/O thread `srt_accept`s a caller as soon as libsrt queues it and puts
//! the socket id in the listener's accept channel; `SrtListener::accept` takes
//! it from there. Until 2026-11 three paths left such a socket open with no
//! owner: a listener dropped while an id waited in its channel, an id the
//! channel refused (full, or its listener already dropped), and an `accept`
//! future dropped after taking an id but before it had built the socket. The
//! socket stayed connected, the I/O thread read and discarded its data, and
//! libsrt answered the caller's packets for it, so the caller saw a healthy
//! connection to nothing — for good. In bilbycast-edge a caller redialling
//! while the listening input's flow restarted landed exactly there: the new
//! listener on the same port never heard from it, and only restarting the
//! caller recovered. Closed, the socket sends the caller a shutdown, and the
//! caller redials.
//!
//! # Why `harness = false`
//!
//! Same reason as `listener_access_control.rs`, whose module docs carry the
//! detail: real SRT sockets start libsrt's worker threads, which outlive the
//! process's static teardown, so the target owns `main` and leaves with
//! `libc::_exit(0)`.

use std::future::Future;
use std::io::Write;
use std::pin::pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use srt_protocol::config::SocketStatus;
use srt_transport::{SrtListener, SrtSocket};

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");

    // `cargo test --test listener_unclaimed -- <part of a name>` runs the
    // cases whose name holds it.
    let filter = std::env::args().skip(1).find(|a| !a.starts_with('-'));
    let selected = |name: &str| filter.as_deref().is_none_or(|f| name.contains(f));
    let mut passed = 0;

    if selected("a_connection_left_in_a_dropped_listener_is_closed") {
        rt.block_on(a_connection_left_in_a_dropped_listener_is_closed());
        println!("test a_connection_left_in_a_dropped_listener_is_closed ... ok");
        passed += 1;
    }

    if selected("an_accept_dropped_part_way_closes_its_connection") {
        rt.block_on(an_accept_dropped_part_way_closes_its_connection());
        println!("test an_accept_dropped_part_way_closes_its_connection ... ok");
        passed += 1;
    }

    if selected("a_connection_the_accept_channel_refuses_is_closed") {
        rt.block_on(a_connection_the_accept_channel_refuses_is_closed());
        println!("test a_connection_the_accept_channel_refuses_is_closed ... ok");
        passed += 1;
    }

    println!("\ntest result: ok. {passed} passed; 0 failed");
    let _ = std::io::stdout().flush();

    // Leave before the C++ static destructors run. See the module docs.
    unsafe { libc::_exit(0) };
}

/// How long a caller whose peer socket was closed may take to see it: the
/// shutdown crosses loopback at once, and the bridge's state poll runs about
/// once a second.
const DROP_SEEN_WITHIN: Duration = Duration::from_secs(3);

async fn listener() -> SrtListener {
    SrtListener::builder()
        .live_mode()
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("listener bind")
}

async fn caller(listener: &SrtListener) -> SrtSocket {
    SrtSocket::builder()
        .live_mode()
        .connect_timeout(Duration::from_secs(3))
        .connect(listener.local_addr())
        .await
        .expect("caller connect")
}

/// Whether `sock` leaves `Connected` within `within`.
async fn drops_within(sock: &SrtSocket, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if sock.status() != SocketStatus::Connected {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Give the I/O thread time to accept what libsrt queued: it polls every
/// 10 ms with a connected socket about, every 100 ms without.
async fn let_the_bridge_accept() {
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// A listener dropped with a caller waiting in its accept channel closes that
/// caller's socket.
async fn a_connection_left_in_a_dropped_listener_is_closed() {
    let listener = listener().await;
    let caller = caller(&listener).await;
    let_the_bridge_accept().await;
    drop(listener);
    assert!(
        drops_within(&caller, DROP_SEEN_WITHIN).await,
        "the caller is still connected {DROP_SEEN_WITHIN:?} after the listener holding its \
         unaccepted socket was dropped: that socket is open with no owner",
    );
}

/// An `accept` future dropped after taking the caller's id, while it was still
/// building the socket, closes it.
async fn an_accept_dropped_part_way_closes_its_connection() {
    let mut listener = listener().await;
    let caller = caller(&listener).await;
    let_the_bridge_accept().await;
    {
        // One poll: the id is waiting, so it is taken at once, and building the
        // socket then waits on the I/O thread's replies.
        let mut accept = pin!(listener.accept());
        let first = std::future::poll_fn(|cx| Poll::Ready(accept.as_mut().poll(cx))).await;
        if let Poll::Ready(accepted) = first {
            // The I/O thread answered within the one poll, so nothing was left
            // part-way; dropping the socket closes it like any other.
            drop(accepted.expect("accept"));
        }
    }
    assert!(
        drops_within(&caller, DROP_SEEN_WITHIN).await,
        "the caller is still connected {DROP_SEEN_WITHIN:?} after the accept that took its \
         socket was dropped part-way: that socket is open with no owner",
    );
    drop(listener);
}

/// A caller the accept channel has no room for (16 others wait unaccepted) is
/// closed, not left open behind the channel; the 16 stay, and are accepted.
async fn a_connection_the_accept_channel_refuses_is_closed() {
    let mut listener = listener().await;
    let mut callers = Vec::new();
    for _ in 0..16 {
        callers.push(caller(&listener).await);
        let_the_bridge_accept().await;
    }
    // Closed at once, the 17th can see the shutdown before its own connect
    // completes, and then its connect fails instead.
    let refused = SrtSocket::builder()
        .live_mode()
        .connect_timeout(Duration::from_secs(3))
        .connect(listener.local_addr())
        .await;
    if let Ok(refused) = refused {
        assert!(
            drops_within(&refused, DROP_SEEN_WITHIN).await,
            "the caller the full accept channel refused is still connected \
             {DROP_SEEN_WITHIN:?} later: its socket is open with no owner",
        );
    }
    for (i, waiting) in callers.iter().enumerate() {
        assert_eq!(waiting.status(), SocketStatus::Connected, "caller {i} waits in the channel");
    }
    let mut accepted = Vec::new();
    for _ in 0..callers.len() {
        accepted.push(listener.accept().await.expect("accept a waiting caller"));
    }
    assert!(accepted.iter().all(|s| s.status() == SocketStatus::Connected));
    drop(accepted);
    drop(listener);
}
