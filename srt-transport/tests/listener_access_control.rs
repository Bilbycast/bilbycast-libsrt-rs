// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! An SRT listener's access-control policy must actually run.
//!
//! Until 2026-08 it never did: `epoll_bridge` registered the accept hook
//! *after* `srt_listen`, and libsrt refuses that — silently. A listener
//! configured with a `stream_id` filter (bilbycast-edge's documented hardening
//! for an SRT listener input) accepted every caller on the internet.
//!
//! # Why this is not a `#[cfg(test)]` module
//!
//! Every assertion below needs a real bound SRT socket, and `srt_bind` starts
//! libsrt's multiplexer / receive-queue worker threads. `srt_cleanup()` never
//! runs in this process — `libsrt-sys` holds its startup guard in a
//! `static OnceLock`, and statics are never dropped — so those threads are
//! still live when the C++ runtime destroys libsrt's globals at exit, and the
//! process dies with SIGSEGV *after* the last assertion has passed. Under the
//! default libtest harness that turns a passing run red at random (measured
//! 18/20 from a bare `srt_startup()` + `srt_bind()`).
//!
//! So this target sets `harness = false` (see `Cargo.toml`), runs the
//! assertions from `main`, and finishes with `libc::_exit(0)` — the process
//! never reaches static teardown. A failed assertion still panics out of
//! `main` and exits non-zero, so the target cannot go green by accident.
//! Everything that does *not* need a bound socket stays in the unit tests in
//! `src/epoll_bridge.rs`, which run under the normal harness.

use std::io::Write;
use std::mem::size_of;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::time::Duration;

use libsrt_sys::*;
use srt_protocol::error::RejectReason;
use srt_transport::{SrtListener, SrtSocket};

fn main() {
    libsrt_refuses_an_accept_hook_once_the_socket_is_listening();
    println!("test libsrt_refuses_an_accept_hook_once_the_socket_is_listening ... ok");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(listener_enforces_its_access_control_policy());
    println!("test listener_enforces_its_access_control_policy ... ok");

    println!("\ntest result: ok. 2 passed; 0 failed");
    let _ = std::io::stdout().flush();

    // Leave before the C++ static destructors run. See the module docs.
    unsafe { libc::_exit(0) };
}

/// The libsrt contract that makes the registration *order* load-bearing.
///
/// `CUDT::installAcceptHook` throws `MJ_NOTSUP / MN_ISCONNECTED` when the
/// socket is already listening (`if (m_bConnected || m_bConnecting ||
/// m_bListening || m_bBroken) throw` — vendored `srtcore/core.h:1167-1172`),
/// and `CUDTUnited::installAcceptHook` swallows it into a plain `SRT_ERROR`
/// (`srtcore/api.cpp:1010-1024`). There is exactly one window in which a hook
/// can be installed, it closes at `srt_listen`, and nothing throws if you miss
/// it — which is how the old bridge shipped a listener whose access control
/// never ran.
///
/// If a libsrt bump ever widens that window this test goes red, and the
/// `Listen` arm's ordering comment needs re-checking rather than trusting.
fn libsrt_refuses_an_accept_hook_once_the_socket_is_listening() {
    libsrt_sys::ensure_initialized();

    unsafe {
        let sock = srt_create_socket();
        assert!(sock >= 0, "srt_create_socket failed");

        let sa = loopback_sockaddr(0);
        assert_eq!(
            srt_bind(
                sock,
                &sa as *const libc::sockaddr_storage as *const std::ffi::c_void as *const _,
                size_of::<libc::sockaddr_storage>() as c_int,
            ),
            0,
            "srt_bind failed",
        );

        assert_eq!(
            srt_listen_callback(sock, Some(accept_everything), ptr::null_mut()),
            0,
            "libsrt refused an accept hook on a bound, not-yet-listening socket \
             — there is now no window at all in which one can be installed",
        );

        assert_eq!(srt_listen(sock, 5), 0, "srt_listen failed");

        assert_eq!(
            srt_listen_callback(sock, Some(accept_everything), ptr::null_mut()),
            -1,
            "libsrt accepted an accept-hook install on a LISTENING socket — the \
             ordering trap is gone; re-check srtcore/core.h installAcceptHook \
             before relaxing the Listen arm in epoll_bridge.rs",
        );

        srt_close(sock);
    }
}

/// End to end over a real loopback SRT handshake: a listener with a
/// `stream_id` access-control policy must enforce it.
///
/// **This is the regression test for the whole finding.** Move the hook
/// registration back after `srt_listen` (or discard its return code) and phase
/// 1 goes red: the wrong-`stream_id` caller is accepted.
async fn listener_enforces_its_access_control_policy() {
    let mut listener = SrtListener::builder()
        .live_mode()
        .access_control_fn(|info| {
            if info.stream_id == "letmein" {
                Ok(())
            } else {
                Err(RejectReason::Peer)
            }
        })
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("listener bind");
    let addr = listener.local_addr();
    assert_ne!(addr.port(), 0, "listener did not report a bound port");

    // Phase 1 — wrong stream id: must never reach `accept()`.
    let rejected = tokio::spawn(async move {
        SrtSocket::builder()
            .live_mode()
            .stream_id("wrong-id".into())
            .connect_timeout(Duration::from_secs(3))
            .connect(addr)
            .await
    });
    let accepted = tokio::time::timeout(Duration::from_secs(4), listener.accept()).await;
    assert!(
        accepted.is_err(),
        "listener accepted a caller whose stream_id the access-control policy \
         rejects — the accept hook never ran",
    );
    let _ = rejected.await;

    // Phase 2 — right stream id: must be accepted. Proves the rig works and
    // that arming the hook does not lock out legitimate callers.
    let admitted = tokio::spawn(async move {
        SrtSocket::builder()
            .live_mode()
            .stream_id("letmein".into())
            .connect_timeout(Duration::from_secs(8))
            .connect(addr)
            .await
    });
    let accepted = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("listener never accepted the caller with the expected stream_id");
    assert!(accepted.is_ok(), "accept failed: {:?}", accepted.err());
    let caller = admitted.await.expect("caller task panicked");
    assert!(caller.is_ok(), "caller connect failed: {:?}", caller.err());
}

/// A hook that admits everyone — only ever registered, never invoked (nothing
/// connects to the socket in that test).
unsafe extern "C" fn accept_everything(
    _opaque: *mut std::ffi::c_void,
    _ns: SRTSOCKET,
    _hs_version: c_int,
    _peeraddr: *const sockaddr,
    _streamid: *const c_char,
) -> c_int {
    0
}

/// `127.0.0.1:port` as a `sockaddr_storage`, mirroring
/// `epoll_bridge::socket_addr_to_sockaddr` (which is crate-private).
fn loopback_sockaddr(port: u16) -> libc::sockaddr_storage {
    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let sin =
        unsafe { &mut *(&mut sa as *mut libc::sockaddr_storage as *mut libc::sockaddr_in) };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_port = port.to_be();
    sin.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        sin.sin_len = size_of::<libc::sockaddr_in>() as u8;
    }
    sa
}
