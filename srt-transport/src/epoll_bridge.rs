// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Dedicated I/O thread bridging libsrt's epoll to Tokio.
//!
//! All libsrt C API calls happen exclusively on one OS thread. Tokio tasks
//! communicate via lock-free channels. This eliminates the need for any
//! Mutex on the data path.
//!
//! # Architecture
//!
//! ```text
//! [Tokio tasks] <--channels--> [I/O Thread (srt_epoll_wait)] <--C API--> [libsrt]
//! ```

use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::net::SocketAddr;
use std::os::raw::{c_char, c_int};
use std::sync::OnceLock;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, watch};

use libsrt_sys::*;
use srt_protocol::config::{CryptoModeConfig, MemberStatus, RetransmitAlgo, SocketStatus, SrtConfig, TransType};
use srt_protocol::error::SrtError;
use srt_protocol::received_packet::ReceivedPacket;
use srt_protocol::stats::SrtStats;
use srt_protocol::access_control::{AccessControl, HandshakeInfo};

use crate::stats_bridge::convert_perfmon_to_stats;
use crate::error::last_srt_error;

/// Opaque identifier for sockets managed by the I/O thread.
pub(crate) type SocketId = i32; // SRTSOCKET is i32

/// Maximum receive buffer size for a single srt_recvmsg2 call.
const RECV_BUF_SIZE: usize = 65536;

/// Maximum epoll events per wait call.
const MAX_EPOLL_EVENTS: usize = 64;

// ── Commands from Tokio tasks to the I/O thread ──

#[allow(dead_code)]
pub(crate) enum IoCommand {
    /// Create a new SRT socket with the given config, apply options.
    CreateSocket {
        config: SrtConfig,
        reply: oneshot::Sender<Result<SocketId, SrtError>>,
    },
    /// Bind a socket to a local address.
    Bind {
        id: SocketId,
        addr: SocketAddr,
        reply: oneshot::Sender<Result<(), SrtError>>,
    },
    /// Start listening on a bound socket.
    Listen {
        id: SocketId,
        backlog: i32,
        reply: oneshot::Sender<Result<(), SrtError>>,
    },
    /// Connect a socket to a remote address.
    Connect {
        id: SocketId,
        addr: SocketAddr,
        reply: oneshot::Sender<Result<(), SrtError>>,
    },
    /// Register channels for a socket (recv data, send data, status updates).
    /// `recv_tx` now carries `ReceivedPacket` (payload + sender timestamp)
    /// so consumers can drive bilbycast-edge's `SenderTimestampMaster`
    /// without a second recv API.
    RegisterSocket {
        id: SocketId,
        recv_tx: mpsc::UnboundedSender<ReceivedPacket>,
        send_rx: mpsc::Receiver<Bytes>,
        status_tx: watch::Sender<SocketStatus>,
    },
    /// Register a listener socket's accept channel.
    RegisterListener {
        id: SocketId,
        accept_tx: mpsc::Sender<SocketId>,
        access_control: Option<Box<dyn AccessControl>>,
    },
    /// Get socket statistics.
    GetStats {
        id: SocketId,
        reply: oneshot::Sender<Result<SrtStats, SrtError>>,
    },
    /// Get socket state.
    GetState {
        id: SocketId,
        reply: oneshot::Sender<SocketStatus>,
    },
    /// Get peer address.
    GetPeerAddr {
        id: SocketId,
        reply: oneshot::Sender<Option<SocketAddr>>,
    },
    /// Get local address.
    GetLocalAddr {
        id: SocketId,
        reply: oneshot::Sender<Option<SocketAddr>>,
    },
    /// Get stream ID from an accepted socket.
    GetStreamId {
        id: SocketId,
        reply: oneshot::Sender<String>,
    },
    /// Close a socket.
    Close {
        id: SocketId,
    },
    /// Create a socket group for bonding.
    CreateGroup {
        mode: SRT_GROUP_TYPE,
        config: SrtConfig,
        reply: oneshot::Sender<Result<SocketId, SrtError>>,
    },
    /// Connect a group to multiple endpoints.
    ConnectGroup {
        id: SocketId,
        endpoints: Vec<SocketAddr>,
        reply: oneshot::Sender<Result<(), SrtError>>,
    },
    /// Get per-member statistics for a socket group (bonding).
    GetGroupMemberStats {
        id: SocketId,
        reply: oneshot::Sender<Vec<crate::group::GroupMemberStats>>,
    },
    /// Shutdown the I/O thread.
    Shutdown,
}

// Send is safe because IoCommand only moves data across threads via channels.
// The AccessControl Box is Send + Sync + 'static by trait bound.
unsafe impl Send for IoCommand {}

/// Per-socket state tracked on the I/O thread.
#[allow(dead_code)]
struct SocketState {
    recv_tx: Option<mpsc::UnboundedSender<ReceivedPacket>>,
    send_rx: Option<mpsc::Receiver<Bytes>>,
    send_backlog: VecDeque<Bytes>,
    status_tx: Option<watch::Sender<SocketStatus>>,
    /// For listener sockets: channel to send accepted socket IDs.
    accept_tx: Option<mpsc::Sender<SocketId>>,
    /// For listener sockets: access control callback.
    access_control: Option<Box<dyn AccessControl>>,
    /// Whether this is a listener socket.
    is_listener: bool,
    /// Whether this is a group socket.
    is_group: bool,
    /// Last known status.
    last_status: SocketStatus,
    /// Pending connect reply (for async connect).
    connect_reply: Option<oneshot::Sender<Result<(), SrtError>>>,
}

/// Handle to the I/O thread. Clone this to send commands.
#[derive(Clone)]
pub(crate) struct IoHandle {
    cmd_tx: mpsc::UnboundedSender<IoCommand>,
}

impl IoHandle {
    pub fn send_command(&self, cmd: IoCommand) {
        let _ = self.cmd_tx.send(cmd);
    }
}

/// Global singleton I/O thread handle.
static IO_HANDLE: OnceLock<IoHandle> = OnceLock::new();

/// Get the global I/O thread handle, spawning the thread if needed.
pub(crate) fn io_handle() -> IoHandle {
    IO_HANDLE
        .get_or_init(|| {
            libsrt_sys::ensure_initialized();
            let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
            std::thread::Builder::new()
                .name("srt-io".into())
                .spawn(move || {
                    io_thread_main(cmd_rx);
                })
                .expect("failed to spawn SRT I/O thread");
            IoHandle { cmd_tx }
        })
        .clone()
}

/// Main loop of the dedicated I/O thread.
fn io_thread_main(mut cmd_rx: mpsc::UnboundedReceiver<IoCommand>) {
    let epoll_id = unsafe { srt_epoll_create() };
    assert!(epoll_id >= 0, "srt_epoll_create failed");

    // Allow empty watch list without throwing — sockets may be temporarily
    // absent during reconnect cycles.
    unsafe {
        srt_epoll_set(epoll_id, SRT_EPOLL_ENABLE_EMPTY as i32);
    }

    let mut sockets: HashMap<SocketId, SocketState> = HashMap::new();
    let mut recv_buf = vec![0u8; RECV_BUF_SIZE];
    let mut state_poll_counter: u32 = 0;
    const STATE_POLL_INTERVAL: u32 = 100; // poll socket state every ~100 iterations (~1s)
    let mut sock_id_buf: Vec<SocketId> = Vec::with_capacity(32); // reusable buffer
    let mut consecutive_epoll_errors: u32 = 0;

    loop {
        // ── Phase 0: Park when completely idle ──────────────────────────
        // When no sockets exist, park the thread until a command arrives.
        // The OS completely deschedules the thread — zero CPU.
        if sockets.is_empty() {
            match cmd_rx.blocking_recv() {
                Some(cmd) => {
                    if !process_command(cmd, epoll_id, &mut sockets) {
                        cleanup(epoll_id, &mut sockets);
                        return;
                    }
                }
                None => {
                    cleanup(epoll_id, &mut sockets);
                    return;
                }
            }
            continue;
        }

        // ── Phase 1: Drain command channel (non-blocking) ──────────────
        loop {
            match cmd_rx.try_recv() {
                Ok(cmd) => {
                    if !process_command(cmd, epoll_id, &mut sockets) {
                        cleanup(epoll_id, &mut sockets);
                        return;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    cleanup(epoll_id, &mut sockets);
                    return;
                }
            }
        }

        // ── Classify socket activity level ─────────────────────────────
        let has_connected = sockets.values().any(|s| {
            matches!(s.last_status, SocketStatus::Connected)
        });
        let has_connecting = !has_connected && sockets.values().any(|s| {
            matches!(s.last_status, SocketStatus::Connecting)
        });

        // ── IDLE PATH: only listeners / broken sockets, nothing active ─
        //
        // srt_epoll_uwait may not reliably block on macOS — it can return
        // immediately (0 or -1) even with a timeout, burning 100% CPU.
        // Instead of trusting the timeout, we do a quick non-blocking
        // epoll check for listener accepts, then explicitly sleep the OS
        // thread. This guarantees near-zero CPU when no peers are around.
        if !has_connected && !has_connecting {
            // Quick non-blocking epoll check (timeout=0) — catches any
            // listener accept or error events that arrived.
            let mut events = vec![SRT_EPOLL_EVENT { fd: 0, events: 0 }; MAX_EPOLL_EVENTS];
            let n = unsafe {
                srt_epoll_uwait(
                    epoll_id,
                    events.as_mut_ptr(),
                    MAX_EPOLL_EVENTS as c_int,
                    0, // non-blocking
                )
            };

            if n > 0 {
                process_epoll_events(
                    &events[..n as usize],
                    epoll_id,
                    &mut sockets,
                    &mut recv_buf,
                );
            }

            // Auto-cleanup zombie sockets while we're here.
            cleanup_zombies(epoll_id, &mut sockets, &mut sock_id_buf);

            // Guaranteed OS sleep — the thread is fully descheduled.
            // 100ms gives sub-second response to incoming SRT callers
            // while using effectively zero CPU.
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }

        // ── ACTIVE PATH: at least one connected or connecting socket ───
        //
        // Use short epoll timeout for fast send-channel drain (connected)
        // or responsive connect-completion detection (connecting).
        let timeout_ms = if has_connected { 10 } else { 100 };

        let mut events = vec![SRT_EPOLL_EVENT { fd: 0, events: 0 }; MAX_EPOLL_EVENTS];
        let n = unsafe {
            srt_epoll_uwait(
                epoll_id,
                events.as_mut_ptr(),
                MAX_EPOLL_EVENTS as c_int,
                timeout_ms,
            )
        };

        if n < 0 {
            // epoll error — sleep to prevent busy-loop on persistent errors.
            consecutive_epoll_errors += 1;
            let backoff_ms = 1u64 << consecutive_epoll_errors.min(7);
            if consecutive_epoll_errors == 10 {
                tracing::warn!(
                    "srt-io: 10 consecutive srt_epoll_uwait errors, backing off to {}ms",
                    backoff_ms,
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
            continue;
        }

        consecutive_epoll_errors = 0;

        if n > 0 {
            process_epoll_events(
                &events[..n as usize],
                epoll_id,
                &mut sockets,
                &mut recv_buf,
            );
        }

        // Drain send channels for all connected sockets (fire-and-forget).
        // Must run every iteration — output sockets don't subscribe to OUT
        // events, so their send channels can only be drained here.
        if has_connected {
            sock_id_buf.clear();
            sock_id_buf.extend(sockets.keys().copied());
            for id in &sock_id_buf {
                if let Some(state) = sockets.get(id) {
                    if state.send_rx.is_some()
                        && matches!(state.last_status, SocketStatus::Connected)
                    {
                        handle_send(*id, &mut sockets);
                    }
                }
            }
        }

        // Check for state changes (poll broken connections).
        // Throttled to every STATE_POLL_INTERVAL iterations (~100ms–1s).
        state_poll_counter += 1;
        if state_poll_counter >= STATE_POLL_INTERVAL {
            state_poll_counter = 0;
            sock_id_buf.clear();
            sock_id_buf.extend(sockets.keys().copied());
            for id in sock_id_buf.iter().copied() {
                let raw_state = unsafe { srt_getsockstate(id) };
                let status = raw_state_to_status(raw_state);

                if let Some(state) = sockets.get_mut(&id) {
                    if status != state.last_status {
                        update_status(state, status);

                        if matches!(status, SocketStatus::Broken | SocketStatus::Closed) {
                            if let Some(reply) = state.connect_reply.take() {
                                let _ = reply.send(Err(last_srt_error()));
                            }
                        }
                    }
                }
            }

            // Auto-cleanup zombie sockets.
            cleanup_zombies(epoll_id, &mut sockets, &mut sock_id_buf);
        }
    }
}

/// Process epoll events (accepts, connects, reads, writes, errors).
fn process_epoll_events(
    events: &[SRT_EPOLL_EVENT],
    epoll_id: c_int,
    sockets: &mut HashMap<SocketId, SocketState>,
    recv_buf: &mut [u8],
) {
    for event in events {
        let sock_id = event.fd;
        let ev = event.events as u32;

        // Listener accept
        if let Some(state) = sockets.get(&sock_id) {
            if state.is_listener && (ev & SRT_EPOLL_IN as u32) != 0 {
                handle_accept(sock_id, epoll_id, sockets);
                continue;
            }
        }

        // Connect completion
        if (ev & SRT_EPOLL_CONNECT as u32) != 0 {
            if let Some(state) = sockets.get_mut(&sock_id) {
                if let Some(reply) = state.connect_reply.take() {
                    let sock_state = unsafe { srt_getsockstate(sock_id) };
                    if sock_state == SRT_SOCKSTATUS_SRTS_CONNECTED {
                        let _ = reply.send(Ok(()));
                        update_status(state, SocketStatus::Connected);
                    } else {
                        let _ = reply.send(Err(last_srt_error()));
                        update_status(state, SocketStatus::Broken);
                    }
                }
            }
        }

        // Readable
        if (ev & SRT_EPOLL_IN as u32) != 0 {
            handle_recv(sock_id, sockets, recv_buf);
        }

        // Writable — drain send queue
        if (ev & SRT_EPOLL_OUT as u32) != 0 {
            handle_send(sock_id, sockets);
        }

        // Errors
        if (ev & SRT_EPOLL_ERR as u32) != 0 {
            if let Some(state) = sockets.get_mut(&sock_id) {
                update_status(state, SocketStatus::Broken);
            }
        }
    }
}

/// Remove zombie sockets: broken/closed, not a listener or group, and the
/// Tokio-side handle has been dropped (recv channel closed).
fn cleanup_zombies(
    epoll_id: c_int,
    sockets: &mut HashMap<SocketId, SocketState>,
    buf: &mut Vec<SocketId>,
) {
    buf.clear();
    for (&id, state) in sockets.iter() {
        if !matches!(state.last_status, SocketStatus::Broken | SocketStatus::Closed) {
            continue;
        }
        if state.is_listener || state.is_group {
            continue;
        }
        let tokio_side_gone = state.recv_tx.as_ref().map_or(true, |tx| tx.is_closed());
        if tokio_side_gone {
            buf.push(id);
        }
    }
    for id in buf.iter().copied() {
        if let Some(state) = sockets.remove(&id) {
            if let Some(reply) = state.connect_reply {
                let _ = reply.send(Err(SrtError::ConnectionLost));
            }
        }
        unsafe { srt_epoll_remove_usock(epoll_id, id) };
        unsafe { srt_close(id) };
    }
}

/// Process a single IoCommand. Returns false if shutdown requested.
fn process_command(
    cmd: IoCommand,
    epoll_id: c_int,
    sockets: &mut HashMap<SocketId, SocketState>,
) -> bool {
    match cmd {
        IoCommand::CreateSocket { config, reply } => {
            let sock = unsafe { srt_create_socket() };
            if sock < 0 {
                let _ = reply.send(Err(last_srt_error()));
                return true;
            }
            // Set non-blocking mode
            set_bool_opt(sock, SRTO_RCVSYN as c_int, false);
            set_bool_opt(sock, SRTO_SNDSYN as c_int, false);
            // Apply all config options
            apply_config(sock, &config);
            let _ = reply.send(Ok(sock));
        }

        IoCommand::Bind { id, addr, reply } => {
            let result = bind_socket(id, addr);
            let _ = reply.send(result);
        }

        IoCommand::Listen { id, backlog, reply } => {
            let ret = unsafe { srt_listen(id, backlog) };
            if ret < 0 {
                let _ = reply.send(Err(last_srt_error()));
            } else {
                // Register listener callback if access control is set
                if let Some(state) = sockets.get(&id) {
                    if state.access_control.is_some() {
                        register_listen_callback(id, sockets);
                    }
                }
                // Add to epoll for accept notifications
                add_to_epoll(epoll_id, id, SRT_EPOLL_IN as c_int | SRT_EPOLL_ERR as c_int);
                if let Some(state) = sockets.get_mut(&id) {
                    state.is_listener = true;
                    update_status(state, SocketStatus::Listening);
                }
                let _ = reply.send(Ok(()));
            }
        }

        IoCommand::Connect { id, addr, reply } => {
            let sa = socket_addr_to_sockaddr(&addr);
            let ret = unsafe {
                srt_connect(
                    id,
                    &sa as *const libc::sockaddr_storage as *const std::ffi::c_void as *const _,
                    std::mem::size_of::<libc::sockaddr_storage>() as c_int,
                )
            };
            // In non-blocking mode, srt_connect returning 0 means "handshake
            // initiated", not "connection established". srt_connect returning
            // -1 with AsyncFail is the same thing. Either way, we must wait
            // for the socket to actually transition to SRTS_CONNECTED before
            // reporting success — otherwise the caller will happily "connect"
            // to a non-existent peer and only discover the truth when the
            // send buffer fills up.
            if ret < 0 {
                let err = last_srt_error();
                if err != SrtError::AsyncFail {
                    let _ = reply.send(Err(err));
                    return true;
                }
                // AsyncFail: fall through to state-based dispatch below.
            }
            let sock_state = unsafe { srt_getsockstate(id) };
            if sock_state == SRT_SOCKSTATUS_SRTS_CONNECTED {
                // Genuine immediate success — rare but possible.
                add_to_epoll(
                    epoll_id,
                    id,
                    SRT_EPOLL_IN as c_int | SRT_EPOLL_ERR as c_int
                        | SRT_EPOLL_ET as c_int,
                );
                if let Some(state) = sockets.get_mut(&id) {
                    update_status(state, SocketStatus::Connected);
                }
                let _ = reply.send(Ok(()));
            } else if sock_state == SRT_SOCKSTATUS_SRTS_CONNECTING
                || sock_state == SRT_SOCKSTATUS_SRTS_OPENED
                || sock_state == SRT_SOCKSTATUS_SRTS_INIT
            {
                // Handshake in progress — wait for EPOLL_CONNECT.
                add_to_epoll(
                    epoll_id,
                    id,
                    SRT_EPOLL_IN as c_int
                        | SRT_EPOLL_ERR as c_int | SRT_EPOLL_CONNECT as c_int
                        | SRT_EPOLL_ET as c_int,
                );
                if let Some(state) = sockets.get_mut(&id) {
                    state.connect_reply = Some(reply);
                    update_status(state, SocketStatus::Connecting);
                }
            } else {
                // BROKEN, CLOSING, CLOSED, NONEXIST — fail immediately.
                let _ = reply.send(Err(last_srt_error()));
            }
        }

        IoCommand::RegisterSocket { id, recv_tx, send_rx, status_tx } => {
            let state = sockets.entry(id).or_insert_with(|| SocketState {
                recv_tx: None,
                send_rx: None,
                send_backlog: VecDeque::new(),
                status_tx: None,
                accept_tx: None,
                access_control: None,
                is_listener: false,
                is_group: false,
                last_status: SocketStatus::Init,
                connect_reply: None,
            });
            state.recv_tx = Some(recv_tx);
            state.send_rx = Some(send_rx);
            state.status_tx = Some(status_tx);

            // Query actual libsrt state — accepted sockets are already Connected
            // but or_insert_with defaults to Init. Correct it here so the send
            // loop drains data immediately instead of waiting for the next
            // STATE_POLL_INTERVAL cycle.
            let raw_state = unsafe { srt_getsockstate(id) };
            let actual_status = raw_state_to_status(raw_state);
            if actual_status != state.last_status {
                update_status(state, actual_status);
            }
        }

        IoCommand::RegisterListener { id, accept_tx, access_control } => {
            let state = sockets.entry(id).or_insert_with(|| SocketState {
                recv_tx: None,
                send_rx: None,
                send_backlog: VecDeque::new(),
                status_tx: None,
                accept_tx: None,
                access_control: None,
                is_listener: true,
                is_group: false,
                last_status: SocketStatus::Init,
                connect_reply: None,
            });
            state.accept_tx = Some(accept_tx);
            if let Some(ac) = access_control {
                state.access_control = Some(ac);
            }
        }

        IoCommand::GetStats { id, reply } => {
            let stats = get_socket_stats(id);
            let _ = reply.send(stats);
        }

        IoCommand::GetState { id, reply } => {
            let raw = unsafe { srt_getsockstate(id) };
            let _ = reply.send(raw_state_to_status(raw));
        }

        IoCommand::GetPeerAddr { id, reply } => {
            let _ = reply.send(get_peer_addr(id));
        }

        IoCommand::GetLocalAddr { id, reply } => {
            let _ = reply.send(get_local_addr(id));
        }

        IoCommand::GetStreamId { id, reply } => {
            let _ = reply.send(get_stream_id(id));
        }

        IoCommand::Close { id } => {
            if let Some(state) = sockets.remove(&id) {
                if let Some(reply) = state.connect_reply {
                    let _ = reply.send(Err(SrtError::SocketClosed));
                }
            }
            unsafe { srt_epoll_remove_usock(epoll_id, id) };
            unsafe { srt_close(id) };
        }

        IoCommand::CreateGroup { mode, config, reply } => {
            let grp = unsafe { srt_create_group(mode) };
            if grp < 0 {
                let _ = reply.send(Err(last_srt_error()));
            } else {
                set_bool_opt(grp, SRTO_RCVSYN as c_int, false);
                set_bool_opt(grp, SRTO_SNDSYN as c_int, false);
                apply_config(grp, &config);

                let state = SocketState {
                    recv_tx: None,
                    send_rx: None,
                send_backlog: VecDeque::new(),
                    status_tx: None,
                    accept_tx: None,
                    access_control: None,
                    is_listener: false,
                    is_group: true,
                    last_status: SocketStatus::Init,
                    connect_reply: None,
                };
                sockets.insert(grp, state);
                let _ = reply.send(Ok(grp));
            }
        }

        IoCommand::ConnectGroup { id, endpoints, reply } => {
            let result = connect_group(id, &endpoints, epoll_id);
            if result.is_ok() {
                add_to_epoll(
                    epoll_id,
                    id,
                    SRT_EPOLL_IN as c_int | SRT_EPOLL_ERR as c_int
                        | SRT_EPOLL_ET as c_int,
                );
                if let Some(state) = sockets.get_mut(&id) {
                    update_status(state, SocketStatus::Connected);
                }
            }
            let _ = reply.send(result);
        }

        IoCommand::GetGroupMemberStats { id, reply } => {
            let members = get_group_member_stats(id);
            let _ = reply.send(members);
        }

        IoCommand::Shutdown => {
            return false;
        }
    }
    true
}

// ── Helper functions (all called on I/O thread only) ──

/// Drain all available messages from the socket's receive buffer.
///
/// We check `SRTO_RCVDATA` before each `srt_recvmsg2` call to avoid hitting
/// libsrt's "no data" exception path (`EASYNCRCV`). C++ stack unwinding is
/// extremely expensive (~98% of srt-io CPU in profiling), so we must never
/// call `srt_recvmsg2` when the buffer is empty.
fn handle_recv(sock_id: SocketId, sockets: &mut HashMap<SocketId, SocketState>, recv_buf: &mut [u8]) {
    loop {
        // Check how many packets are buffered before attempting recv.
        // This avoids the C++ exception that srt_recvmsg2 throws on empty buffer.
        let mut rcv_data: i32 = 0;
        let mut optlen: c_int = std::mem::size_of::<i32>() as c_int;
        let ok = unsafe {
            srt_getsockflag(
                sock_id,
                SRTO_RCVDATA,
                &mut rcv_data as *mut i32 as *mut std::ffi::c_void,
                &mut optlen,
            )
        };
        if ok < 0 || rcv_data <= 0 {
            break; // No data available or socket error — exit without calling recv
        }

        // Allocate msgctrl on the I/O thread's stack so we can read
        // `srctime` (sender-set delivery timestamp in µs since epoch).
        // bilbycast-edge's master-clock uses this for clock recovery
        // on internet-contribution paths where MPEG-TS PCR sampled
        // from the bytes after the TSBPD latency buffer is too bursty
        // for the PLL to lock. libsrt zeroes the struct on each call;
        // we only read it after a successful recv.
        let mut msgctrl: SRT_MsgCtrl_ = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            srt_recvmsg2(
                sock_id,
                recv_buf.as_mut_ptr() as *mut c_char,
                recv_buf.len() as c_int,
                &mut msgctrl as *mut SRT_MsgCtrl_,
            )
        };
        if ret <= 0 {
            break; // Unexpected: RCVDATA said data exists but recv failed
        }
        let data = Bytes::copy_from_slice(&recv_buf[..ret as usize]);
        // srctime == 0 ⇒ the sender's msgctrl was NULL on srt_sendmsg2
        // and libsrt didn't propagate a timestamp. `ReceivedPacket::with_srctime`
        // maps 0 to `None` so consumers fall through to PCR-from-bytes
        // recovery; non-zero values feed the sender-timestamp master.
        let pkt = ReceivedPacket::with_srctime(data, msgctrl.srctime);
        if let Some(state) = sockets.get(&sock_id) {
            if let Some(ref tx) = state.recv_tx {
                let _ = tx.send(pkt);
            }
        }
    }
}

fn handle_send(sock_id: SocketId, sockets: &mut HashMap<SocketId, SocketState>) {
    let state = match sockets.get_mut(&sock_id) {
        Some(s) => s,
        None => return,
    };

    // First drain any backlogged data from a previous would-block
    while let Some(data) = state.send_backlog.pop_front() {
        let ret = unsafe {
            srt_sendmsg2(
                sock_id,
                data.as_ptr() as *const c_char,
                data.len() as c_int,
                std::ptr::null_mut(),
            )
        };
        if ret < 0 {
            let err = last_srt_error();
            if err == SrtError::AsyncSend {
                // Would block — put back and wait for next writable event
                state.send_backlog.push_front(data);
                return;
            }
            // Connection error — drop the data, status will be updated by epoll
            return;
        }
    }

    // Then drain the send channel (non-blocking)
    if let Some(ref mut rx) = state.send_rx {
        loop {
            match rx.try_recv() {
                Ok(data) => {
                    let ret = unsafe {
                        srt_sendmsg2(
                            sock_id,
                            data.as_ptr() as *const c_char,
                            data.len() as c_int,
                            std::ptr::null_mut(),
                        )
                    };
                    if ret < 0 {
                        let err = last_srt_error();
                        if err == SrtError::AsyncSend {
                            // Would block — backlog this packet for next writable event
                            state.send_backlog.push_back(data);
                            return;
                        }
                        // Connection error — stop sending
                        return;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
    }
}

fn handle_accept(
    listener_id: SocketId,
    epoll_id: c_int,
    sockets: &mut HashMap<SocketId, SocketState>,
) {
    let mut sa_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut sa_len = std::mem::size_of::<libc::sockaddr_storage>() as c_int;

    let accepted = unsafe {
        srt_accept(
            listener_id,
            &mut sa_storage as *mut libc::sockaddr_storage as *mut std::ffi::c_void as *mut _,
            &mut sa_len,
        )
    };

    if accepted < 0 {
        return; // Accept failed
    }

    // Set non-blocking on accepted socket
    set_bool_opt(accepted, SRTO_RCVSYN as c_int, false);
    set_bool_opt(accepted, SRTO_SNDSYN as c_int, false);

    // Add accepted socket to epoll (edge-triggered IN + ERR only — no OUT
    // to avoid busy-loop; sends are drained via the periodic send-channel
    // sweep). ET ensures IN fires once per new data batch; handle_recv
    // drains all buffered data via RCVDATA check, then uwait sleeps.
    add_to_epoll(
        epoll_id,
        accepted,
        SRT_EPOLL_IN as c_int | SRT_EPOLL_ERR as c_int
            | SRT_EPOLL_ET as c_int,
    );

    // Notify the listener's accept channel
    if let Some(state) = sockets.get(&listener_id) {
        if let Some(ref tx) = state.accept_tx {
            let _ = tx.try_send(accepted);
        }
    }
}

fn register_listen_callback(listener_id: SocketId, sockets: &mut HashMap<SocketId, SocketState>) {
    // We need to set up the listen callback. libsrt calls the callback from its
    // internal accept thread. We use a thin C-compatible wrapper that invokes
    // the Rust AccessControl trait.
    //
    // The callback receives an opaque pointer which we use to pass the AccessControl.
    // We Box::leak the Arc to give it 'static lifetime, and clean up on socket close.

    let state = match sockets.get_mut(&listener_id) {
        Some(s) => s,
        None => return,
    };

    if let Some(ac) = state.access_control.take() {
        // Double-box: Box<dyn AccessControl> -> Box<Box<dyn AccessControl>>
        // This gives us a thin *mut Box<dyn AccessControl> that's safe to
        // round-trip through *mut c_void (fat pointers can't survive that cast).
        let ac_ptr = Box::into_raw(Box::new(ac));

        unsafe {
            srt_listen_callback(
                listener_id,
                Some(listen_callback_trampoline),
                ac_ptr as *mut std::ffi::c_void,
            );
        }

        // Store the raw pointer back so we can free it on close
        state.access_control = Some(unsafe { *Box::from_raw(ac_ptr) });
    }
}

/// C-compatible callback for srt_listen_callback.
/// Called from libsrt's internal accept thread.
unsafe extern "C" fn listen_callback_trampoline(
    opaque: *mut std::ffi::c_void,
    _ns: SRTSOCKET,
    _hs_version: c_int,
    peeraddr: *const sockaddr,
    streamid: *const ::std::os::raw::c_char,
) -> c_int {
    if opaque.is_null() {
        return 0; // Accept if no callback
    }

    let ac = &**(opaque as *const Box<dyn AccessControl>);

    // Build HandshakeInfo
    let peer_addr = sockaddr_to_socket_addr(peeraddr as *const std::ffi::c_void as *const libc::sockaddr);
    let stream_id = if streamid.is_null() {
        String::new()
    } else {
        std::ffi::CStr::from_ptr(streamid)
            .to_string_lossy()
            .into_owned()
    };

    let info = HandshakeInfo {
        peer_addr: peer_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
        stream_id,
        is_encrypted: false, // libsrt doesn't expose this in the callback
        peer_socket_id: 0,   // Not available in callback
        peer_version: _hs_version,
    };

    match ac.on_accept(&info) {
        Ok(()) => 0,  // Accept
        Err(_) => -1, // Reject
    }
}

fn apply_config(sock: SocketId, config: &SrtConfig) {
    // Transport type
    match config.trans_type {
        TransType::Live => set_i32_opt(sock, SRTO_TRANSTYPE as c_int, SRTT_LIVE as i32),
        TransType::File => set_i32_opt(sock, SRTO_TRANSTYPE as c_int, SRTT_FILE as i32),
    }

    // Latency
    if config.recv_latency > 0 {
        set_i32_opt(sock, SRTO_RCVLATENCY as c_int, config.recv_latency as i32);
    }
    if config.peer_latency > 0 {
        set_i32_opt(sock, SRTO_PEERLATENCY as c_int, config.peer_latency as i32);
    }

    // MSS
    if config.mss != 1500 {
        set_i32_opt(sock, SRTO_MSS as c_int, config.mss as i32);
    }

    // Flight flag size
    if config.flight_flag_size != 25600 {
        set_i32_opt(sock, SRTO_FC as c_int, config.flight_flag_size as i32);
    }

    // Buffer sizes
    if config.send_buffer_size != 8192 * 1316 {
        set_i32_opt(sock, SRTO_SNDBUF as c_int, config.send_buffer_size as i32);
    }
    if config.recv_buffer_size != 8192 * 1316 {
        set_i32_opt(sock, SRTO_RCVBUF as c_int, config.recv_buffer_size as i32);
    }

    // Peer idle timeout
    let peer_idle_ms = config.peer_idle_timeout.as_millis() as i32;
    if peer_idle_ms > 0 {
        set_i32_opt(sock, SRTO_PEERIDLETIMEO as c_int, peer_idle_ms);
    }

    // Connect timeout
    let conn_timeout_ms = config.connect_timeout.as_millis() as i32;
    if conn_timeout_ms > 0 {
        set_i32_opt(sock, SRTO_CONNTIMEO as c_int, conn_timeout_ms);
    }

    // Payload size
    if config.payload_size > 0 {
        set_i32_opt(sock, SRTO_PAYLOADSIZE as c_int, config.payload_size as i32);
    }

    // Encryption
    if !config.passphrase.is_empty() {
        set_str_opt(sock, SRTO_PASSPHRASE as c_int, &config.passphrase);
        set_i32_opt(sock, SRTO_PBKEYLEN as c_int, config.key_size as i32);
        if config.crypto_mode == CryptoModeConfig::AesGcm {
            // SRTO_CRYPTOMODE: 0 = auto (CTR), 1 = AES-CTR, 2 = AES-GCM
            set_i32_opt(sock, SRTO_CRYPTOMODE as c_int, 2);
        }
    }

    // Enforced encryption
    set_bool_opt(sock, SRTO_ENFORCEDENCRYPTION as c_int, config.enforced_encryption);

    // Bandwidth
    if config.max_bw >= 0 {
        set_i64_opt(sock, SRTO_MAXBW as c_int, config.max_bw);
    }
    if config.input_bw > 0 {
        set_i64_opt(sock, SRTO_INPUTBW as c_int, config.input_bw);
    }
    if config.overhead_bw != 25 {
        set_i32_opt(sock, SRTO_OHEADBW as c_int, config.overhead_bw);
    }
    if config.max_rexmit_bw != -1 {
        set_i64_opt(sock, SRTO_MAXREXMITBW as c_int, config.max_rexmit_bw);
    }

    // Stream ID
    if !config.stream_id.is_empty() {
        set_str_opt(sock, SRTO_STREAMID as c_int, &config.stream_id);
    }

    // Packet filter (FEC)
    if !config.packet_filter.is_empty() {
        set_str_opt(sock, SRTO_PACKETFILTER as c_int, &config.packet_filter);
    }

    // IP options
    if config.ip_tos != 0 {
        set_i32_opt(sock, SRTO_IPTOS as c_int, config.ip_tos);
    }
    if config.ip_ttl != 64 {
        set_i32_opt(sock, SRTO_IPTTL as c_int, config.ip_ttl);
    }

    // Retransmit algo
    if config.retransmit_algo == RetransmitAlgo::Reduced {
        set_i32_opt(sock, SRTO_RETRANSMITALGO as c_int, 1);
    }

    // Drop delay
    if config.send_drop_delay != -1 {
        set_i32_opt(sock, SRTO_SNDDROPDELAY as c_int, config.send_drop_delay);
    }

    // Loss max TTL (reorder tolerance)
    if config.loss_max_ttl > 0 {
        set_i32_opt(sock, SRTO_LOSSMAXTTL as c_int, config.loss_max_ttl);
    }

    // Key material refresh
    if config.km_refresh_rate != 0x0100_0000 {
        set_i32_opt(sock, SRTO_KMREFRESHRATE as c_int, config.km_refresh_rate as i32);
    }
    if config.km_pre_announce != 0x1000 {
        set_i32_opt(sock, SRTO_KMPREANNOUNCE as c_int, config.km_pre_announce as i32);
    }

    // TLPKT drop
    set_bool_opt(sock, SRTO_TLPKTDROP as c_int, config.tlpkt_drop);

    // Rendezvous
    if config.rendezvous {
        set_bool_opt(sock, SRTO_RENDEZVOUS as c_int, true);
    }

    // Group connect
    if config.group_connect {
        set_bool_opt(sock, SRTO_GROUPCONNECT as c_int, true);
    }
}

fn bind_socket(sock: SocketId, addr: SocketAddr) -> Result<(), SrtError> {
    let sa = socket_addr_to_sockaddr(&addr);
    let ret = unsafe {
        srt_bind(
            sock,
            &sa as *const libc::sockaddr_storage as *const std::ffi::c_void as *const _,
            std::mem::size_of::<libc::sockaddr_storage>() as c_int,
        )
    };
    if ret < 0 {
        Err(last_srt_error())
    } else {
        Ok(())
    }
}

fn connect_group(
    grp: SocketId,
    endpoints: &[SocketAddr],
    _epoll_id: c_int,
) -> Result<(), SrtError> {
    if endpoints.is_empty() {
        return Err(SrtError::InvalidParam);
    }

    let mut targets: Vec<SRT_SOCKGROUPCONFIG> = Vec::with_capacity(endpoints.len());
    for addr in endpoints {
        let sa = socket_addr_to_sockaddr(addr);
        let target = unsafe {
            srt_prepare_endpoint(
                std::ptr::null(),
                &sa as *const libc::sockaddr_storage as *const std::ffi::c_void as *const _,
                std::mem::size_of::<libc::sockaddr_storage>() as c_int,
            )
        };
        targets.push(target);
    }

    let ret = unsafe {
        srt_connect_group(
            grp,
            targets.as_mut_ptr(),
            targets.len() as c_int,
        )
    };

    if ret < 0 {
        Err(last_srt_error())
    } else {
        Ok(())
    }
}

fn get_socket_stats(sock: SocketId) -> Result<SrtStats, SrtError> {
    let mut perf: CBytePerfMon = unsafe { std::mem::zeroed() };
    let ret = unsafe { srt_bistats(sock, &mut perf, 0, 1) };
    if ret < 0 {
        Err(last_srt_error())
    } else {
        Ok(convert_perfmon_to_stats(&perf))
    }
}

#[allow(non_upper_case_globals)]
fn map_member_status(raw: SRT_MEMBERSTATUS) -> MemberStatus {
    match raw {
        SRT_MemberStatus_SRT_GST_PENDING => MemberStatus::Pending,
        SRT_MemberStatus_SRT_GST_IDLE => MemberStatus::Idle,
        SRT_MemberStatus_SRT_GST_RUNNING => MemberStatus::Running,
        SRT_MemberStatus_SRT_GST_BROKEN => MemberStatus::Broken,
        _ => MemberStatus::Broken,
    }
}

/// Enumerate a socket group's current members and fetch per-member
/// stats. On any libsrt error (e.g. the group has been closed) returns
/// an empty vec — per-leg stats are a best-effort snapshot.
fn get_group_member_stats(group_id: SocketId) -> Vec<crate::group::GroupMemberStats> {
    // Probe required size. The first call with a null buffer and inoutlen=0
    // returns the number of member slots libsrt wants to fill.
    let mut count: usize = 0;
    let ret =
        unsafe { srt_group_data(group_id, std::ptr::null_mut(), &mut count as *mut usize) };
    // srt_group_data returns -1 when the output is too small but sets
    // `count` to the required length. An error with count==0 means the
    // group is gone.
    if ret < 0 && count == 0 {
        return Vec::new();
    }
    if count == 0 {
        return Vec::new();
    }
    let mut buf: Vec<SRT_SOCKGROUPDATA> = vec![unsafe { std::mem::zeroed() }; count];
    let ret =
        unsafe { srt_group_data(group_id, buf.as_mut_ptr(), &mut count as *mut usize) };
    if ret < 0 {
        return Vec::new();
    }
    buf.truncate(count);
    buf.into_iter()
        .map(|m| {
            // Map peer address. libsrt fills sockaddr_storage for the remote.
            let peer_addr = {
                // SRT's sockaddr_storage mirrors libc's layout.
                let sa: libc::sockaddr_storage =
                    unsafe { std::mem::transmute_copy(&m.peeraddr) };
                sockaddr_storage_to_socket_addr(&sa)
            };
            let socket_status = raw_state_to_status(m.sockstate);
            let member_status = map_member_status(m.memberstate);
            // Per-member SRT stats. Broken members may fail — use zeroed
            // defaults so the caller still sees the member entry.
            let stats = get_socket_stats(m.id).unwrap_or_default();
            crate::group::GroupMemberStats {
                id: m.id,
                peer_addr,
                socket_status,
                member_status,
                weight: m.weight,
                stats,
            }
        })
        .collect()
}

fn get_peer_addr(sock: SocketId) -> Option<SocketAddr> {
    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut sa_len = std::mem::size_of::<libc::sockaddr_storage>() as c_int;
    let ret = unsafe {
        srt_getpeername(
            sock,
            &mut sa as *mut libc::sockaddr_storage as *mut std::ffi::c_void as *mut _,
            &mut sa_len,
        )
    };
    if ret < 0 {
        None
    } else {
        sockaddr_storage_to_socket_addr(&sa)
    }
}

fn get_local_addr(sock: SocketId) -> Option<SocketAddr> {
    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut sa_len = std::mem::size_of::<libc::sockaddr_storage>() as c_int;
    let ret = unsafe {
        srt_getsockname(
            sock,
            &mut sa as *mut libc::sockaddr_storage as *mut std::ffi::c_void as *mut _,
            &mut sa_len,
        )
    };
    if ret < 0 {
        None
    } else {
        sockaddr_storage_to_socket_addr(&sa)
    }
}

fn get_stream_id(sock: SocketId) -> String {
    let mut buf = vec![0u8; 513];
    let mut len = buf.len() as c_int;
    let ret = unsafe {
        srt_getsockflag(
            sock,
            SRTO_STREAMID as SRT_SOCKOPT,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            &mut len,
        )
    };
    if ret < 0 || len <= 0 {
        return String::new();
    }
    String::from_utf8_lossy(&buf[..len as usize]).trim_end_matches('\0').to_string()
}

fn add_to_epoll(epoll_id: c_int, sock: SocketId, events: c_int) {
    let mut ev = events;
    unsafe {
        srt_epoll_add_usock(epoll_id, sock, &mut ev);
    }
}

fn update_status(state: &mut SocketState, status: SocketStatus) {
    state.last_status = status;
    if let Some(ref tx) = state.status_tx {
        let _ = tx.send(status);
    }
    // On terminal states, drop the recv_tx so the Tokio-side recv() unblocks
    // with ConnectionLost. Without this, callers hang forever on dead sockets
    // because the channel sender is still held by the I/O thread.
    if matches!(status, SocketStatus::Broken | SocketStatus::Closed) {
        state.recv_tx = None;
    }
}

fn cleanup(epoll_id: c_int, sockets: &mut HashMap<SocketId, SocketState>) {
    for (id, state) in sockets.drain() {
        if let Some(reply) = state.connect_reply {
            let _ = reply.send(Err(SrtError::SocketClosed));
        }
        unsafe {
            srt_epoll_remove_usock(epoll_id, id);
            srt_close(id);
        }
    }
    unsafe {
        srt_epoll_release(epoll_id);
    }
}

fn raw_state_to_status(raw: SRT_SOCKSTATUS) -> SocketStatus {
    match raw {
        SRTS_INIT => SocketStatus::Init,
        SRTS_OPENED => SocketStatus::Opened,
        SRTS_LISTENING => SocketStatus::Listening,
        SRTS_CONNECTING => SocketStatus::Connecting,
        SRTS_CONNECTED => SocketStatus::Connected,
        SRTS_BROKEN => SocketStatus::Broken,
        SRTS_CLOSING => SocketStatus::Closing,
        SRTS_CLOSED => SocketStatus::Closed,
        SRTS_NONEXIST => SocketStatus::NonExist,
        _ => SocketStatus::NonExist,
    }
}

// ── Socket option helpers ──

fn set_i32_opt(sock: SocketId, opt: c_int, val: i32) {
    unsafe {
        srt_setsockflag(
            sock,
            opt as SRT_SOCKOPT,
            &val as *const i32 as *const std::ffi::c_void,
            std::mem::size_of::<i32>() as c_int,
        );
    }
}

fn set_i64_opt(sock: SocketId, opt: c_int, val: i64) {
    unsafe {
        srt_setsockflag(
            sock,
            opt as SRT_SOCKOPT,
            &val as *const i64 as *const std::ffi::c_void,
            std::mem::size_of::<i64>() as c_int,
        );
    }
}

fn set_bool_opt(sock: SocketId, opt: c_int, val: bool) {
    let v: c_int = if val { 1 } else { 0 };
    unsafe {
        srt_setsockflag(
            sock,
            opt as SRT_SOCKOPT,
            &v as *const c_int as *const std::ffi::c_void,
            std::mem::size_of::<c_int>() as c_int,
        );
    }
}

fn set_str_opt(sock: SocketId, opt: c_int, val: &str) {
    if let Ok(cstr) = CString::new(val) {
        unsafe {
            srt_setsockflag(
                sock,
                opt as SRT_SOCKOPT,
                cstr.as_ptr() as *const std::ffi::c_void,
                val.len() as c_int,
            );
        }
    }
}

// ── Address conversion helpers ──

fn socket_addr_to_sockaddr(addr: &SocketAddr) -> libc::sockaddr_storage {
    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sin = unsafe { &mut *(&mut sa as *mut libc::sockaddr_storage as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
            {
                sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
        }
        SocketAddr::V6(v6) => {
            let sin6 = unsafe { &mut *(&mut sa as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_scope_id = v6.scope_id();
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
            {
                sin6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
            }
        }
    }
    sa
}

fn sockaddr_storage_to_socket_addr(sa: &libc::sockaddr_storage) -> Option<SocketAddr> {
    unsafe { sockaddr_to_socket_addr(sa as *const libc::sockaddr_storage as *const std::ffi::c_void as *const libc::sockaddr) }
}

unsafe fn sockaddr_to_socket_addr(sa: *const libc::sockaddr) -> Option<SocketAddr> {
    if sa.is_null() {
        return None;
    }
    let family = unsafe { (*sa).sa_family as i32 };
    match family {
        libc::AF_INET => {
            let sin = unsafe { &*(sa as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Some(SocketAddr::new(ip.into(), port))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(sa as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Some(SocketAddr::new(ip.into(), port))
        }
        _ => None,
    }
}
