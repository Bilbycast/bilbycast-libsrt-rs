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

/// Owner of the heap slot whose address is handed to libsrt as the
/// `srt_listen_callback` opaque.
///
/// `Box<dyn AccessControl>` is a *fat* pointer, so it cannot survive a
/// round-trip through `*mut c_void`. The slot therefore double-boxes: the
/// outer allocation holds the fat pointer, and its (thin) address is what
/// libsrt stores and hands back to [`listen_callback_trampoline`], which
/// reads the fat pointer out of it.
///
/// **The outer allocation is the thing libsrt points at, and it must outlive
/// every possible invocation of the hook.** Until 2026-08 this code did
/// `state.access_control = Some(*Box::from_raw(ac_ptr))` immediately after
/// registering: moving out of a `Box` frees the box's allocation, so the
/// address libsrt held was dangling from that instant — the trampoline would
/// have read a fat pointer (data + vtable) out of freed heap and made an
/// indirect call through it. (It never actually got the chance; see
/// [`register_listen_callback`] for why the hook was never installed at all.)
/// Owning the raw pointer here instead means the allocation is reachable
/// *only* through the pointer libsrt was given and is freed exactly once, by
/// this `Drop`, when the `SocketState` leaves the map.
///
/// Freeing is safe at that point **only because the socket is closed first** —
/// see [`close_and_release`] for the libsrt locking argument.
struct AccessControlSlot {
    ptr: *mut Box<dyn AccessControl>,
}

impl AccessControlSlot {
    fn new(ac: Box<dyn AccessControl>) -> Self {
        Self { ptr: Box::into_raw(Box::new(ac)) }
    }

    /// The opaque pointer to hand to `srt_listen_callback`.
    fn opaque(&self) -> *mut std::ffi::c_void {
        self.ptr as *mut std::ffi::c_void
    }
}

impl Drop for AccessControlSlot {
    fn drop(&mut self) {
        // Reclaims the outer allocation and drops the `AccessControl` itself.
        drop(unsafe { Box::from_raw(self.ptr) });
    }
}

/// Per-socket state tracked on the I/O thread.
#[allow(dead_code)]
struct SocketState {
    recv_tx: Option<mpsc::UnboundedSender<ReceivedPacket>>,
    send_rx: Option<mpsc::Receiver<Bytes>>,
    send_backlog: VecDeque<Bytes>,
    status_tx: Option<watch::Sender<SocketStatus>>,
    /// For listener sockets: channel to send accepted socket IDs.
    accept_tx: Option<mpsc::Sender<SocketId>>,
    /// For listener sockets: access control callback, in the stable heap slot
    /// whose address libsrt holds. Never sent across threads: every
    /// `SocketState` is created, mutated and dropped inside `io_thread_main`,
    /// which is why the raw pointer inside (making this type `!Send`) is
    /// sound. The *pointee* is reached concurrently by libsrt's receive-queue
    /// worker, which is sound because `AccessControl: Send + Sync` and the
    /// trampoline only ever takes a shared reference to it.
    access_control: Option<AccessControlSlot>,
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
        if !is_terminal_status(state.last_status) {
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
        // Close before dropping the state, for the reason spelled out on
        // `close_and_release`. Listeners are filtered out above so no
        // `AccessControlSlot` can reach here today, but the ordering is the
        // invariant, not the current filter.
        if let Some(state) = close_and_release(epoll_id, id, sockets) {
            if let Some(reply) = state.connect_reply {
                let _ = reply.send(Err(SrtError::ConnectionLost));
            }
        }
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
            // The access-control hook MUST be armed before `srt_listen` —
            // libsrt refuses to install it on an already-listening socket, and
            // silently, at that. See `register_listen_callback`.
            //
            // Fail closed. A listener whose configured filter could not be
            // armed would accept every caller while the operator believes the
            // filter is running; refusing to listen at all surfaces that as a
            // bind failure instead of as a silently open ingress port.
            //
            // Both failure exits **release the socket**. The only sender of
            // this command is `SrtListenerBuilder::bind`, which propagates the
            // error with `?` before an `SrtListener` exists — and `SrtListener`
            // is the only thing that ever sends `Close`. Leaving the socket
            // behind would therefore park an already-`srt_bind`ed socket in
            // libsrt for the life of the process (the zombie reaper skips
            // listeners), holding its UDP port with nothing left that could
            // close it: the caller's next bind retry would get EADDRINUSE and
            // report a port conflict against itself.
            if let Err(err) = register_listen_callback(id, sockets) {
                tracing::error!(
                    "srt-io: refusing to listen on socket {}: access-control hook \
                     could not be installed ({:?}) — listening would silently \
                     accept every caller",
                    id,
                    err,
                );
                close_and_release(epoll_id, id, sockets);
                let _ = reply.send(Err(err));
                return true;
            }
            let ret = unsafe { srt_listen(id, backlog) };
            if ret < 0 {
                // Read the error before `srt_close`, which overwrites it.
                let err = last_srt_error();
                close_and_release(epoll_id, id, sockets);
                let _ = reply.send(Err(err));
            } else {
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
                state.access_control = Some(AccessControlSlot::new(ac));
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
            if let Some(state) = close_and_release(epoll_id, id, sockets) {
                if let Some(reply) = state.connect_reply {
                    let _ = reply.send(Err(SrtError::SocketClosed));
                }
            }
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

/// Close a socket in libsrt and *then* release its Rust-side state, returning
/// whatever state was still registered.
///
/// **The order is a memory-safety requirement, not tidiness.** For a listener
/// carrying an [`AccessControlSlot`], dropping the state frees the allocation
/// whose address libsrt holds as the accept-hook opaque, so it must not happen
/// while the hook can still run.
///
/// `srt_close` on a listening socket gives exactly that guarantee,
/// synchronously (paths in the vendored libsrt v1.5.6):
///   * `CUDTUnited::close` takes the `SRTS_LISTENING` branch and calls
///     `notListening()` before returning (api.cpp:2172-2195);
///   * `notListening()` calls `CRcvQueue::removeListener()`
///     (core.cpp:6583-6590);
///   * `removeListener` is `m_pListener.compare_exchange(u, NULL)`, which takes
///     an EXCLUSIVE lock on the queue's listener slot (queue.cpp:1763-1765,
///     sync.h `CSharedObjectPtr`);
///   * the receive-queue worker holds a SHARED lock on that same slot across
///     the whole of `processConnectRequest` → `newConnection` →
///     `runAcceptHook` → [`listen_callback_trampoline`] (queue.cpp:1454-1471).
///
/// So the exclusive acquisition blocks until any in-flight hook has returned,
/// and once it completes `m_pListener` is NULL and no new invocation can start.
/// A second close is a no-op (`if (s->core().m_bBroken) return 0;`,
/// api.cpp:2174) but by then the first close already unhooked it.
///
/// Closing an id libsrt no longer knows about is harmless — `locateSocket`
/// misses and `srt_close` returns `SRT_ERROR` — so this is safe on the
/// listener-setup failure paths, where the socket may never have reached a
/// listening state at all.
fn close_and_release(
    epoll_id: c_int,
    id: SocketId,
    sockets: &mut HashMap<SocketId, SocketState>,
) -> Option<SocketState> {
    unsafe { srt_epoll_remove_usock(epoll_id, id) };
    unsafe { srt_close(id) };
    sockets.remove(&id)
}

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

/// Arm the listener's access-control hook.
///
/// **Call order matters and libsrt will not tell you if you get it wrong.**
/// `CUDT::installAcceptHook` throws `MJ_NOTSUP / MN_ISCONNECTED` when the
/// socket is already listening (`if (m_bConnected || m_bConnecting ||
/// m_bListening || m_bBroken) throw` — vendored `srtcore/core.h:1167-1172`),
/// and `CUDTUnited::installAcceptHook` swallows that into a plain `SRT_ERROR`
/// return code (`srtcore/api.cpp:1010-1024`). Until 2026-08 this bridge called
/// it *after* `srt_listen` and discarded the return value, so the hook was
/// never installed on any listener: every configured `AccessControl` — in
/// bilbycast-edge, the `stream_id` filter that is the documented hardening for
/// an SRT listener input — was inert, and the listener accepted every caller.
/// Verified against the vendored libsrt: `srt_listen_callback` after
/// `srt_listen` returns `-1` / "Cannot do this operation on a CONNECTED or
/// LISTENING socket"; before it, `0`.
///
/// Returns `Ok(())` when the socket has no access control (nothing to arm) or
/// the hook was accepted. The caller must treat an `Err` as fatal to the
/// listen: an unarmed filter is an open door.
fn register_listen_callback(
    listener_id: SocketId,
    sockets: &HashMap<SocketId, SocketState>,
) -> Result<(), SrtError> {
    let Some(state) = sockets.get(&listener_id) else {
        return Ok(());
    };
    let Some(slot) = state.access_control.as_ref() else {
        return Ok(());
    };

    // The opaque stays owned by `slot`, i.e. by this socket's `SocketState`,
    // and is freed only once the socket has been closed (see
    // [`close_and_release`]). Handing libsrt a pointer we then free — which is
    // what this function used to do — leaves the trampoline reading a fat
    // pointer out of freed heap.
    let ret = unsafe {
        srt_listen_callback(
            listener_id,
            Some(listen_callback_trampoline),
            slot.opaque(),
        )
    };
    if ret < 0 {
        return Err(last_srt_error());
    }
    Ok(())
}

/// C-compatible callback for `srt_listen_callback`.
///
/// Called by libsrt from its receive-queue worker thread, on the handshake of
/// an *unauthenticated* caller — so it is remote-reachable input and must be
/// conservative. `opaque` is the address of the `Box<dyn AccessControl>` owned
/// by the listener's [`AccessControlSlot`]; reading the fat pointer out of it
/// is sound only because that slot outlives `srt_close` on the listener.
unsafe extern "C" fn listen_callback_trampoline(
    opaque: *mut std::ffi::c_void,
    _ns: SRTSOCKET,
    hs_version: c_int,
    peeraddr: *const sockaddr,
    streamid: *const ::std::os::raw::c_char,
) -> c_int {
    if opaque.is_null() {
        return 0; // Accept if no callback
    }

    // Unwinding out of an `extern "C"` function aborts the process. The body
    // below runs operator-supplied code (`on_accept`) and allocates, so a panic
    // here would take a live broadcast node down from a remote peer's
    // handshake. Catch it and fail closed — rejecting one caller is strictly
    // better than aborting, and a panicking access-control decision must never
    // be read as "accept".
    let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ac: &dyn AccessControl = unsafe { &**(opaque as *const Box<dyn AccessControl>) };

        let peer_addr = unsafe {
            sockaddr_to_socket_addr(
                peeraddr as *const std::ffi::c_void as *const libc::sockaddr,
            )
        };
        let stream_id = if streamid.is_null() {
            String::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(streamid) }
                .to_string_lossy()
                .into_owned()
        };

        let info = HandshakeInfo {
            peer_addr: peer_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
            stream_id,
            is_encrypted: false, // libsrt doesn't expose this in the callback
            peer_socket_id: 0,   // Not available in callback
            peer_version: hs_version,
        };

        ac.on_accept(&info)
    }));

    match verdict {
        Ok(Ok(())) => 0,  // Accept
        Ok(Err(_)) => -1, // Reject
        Err(_) => {
            tracing::error!(
                "srt-io: access-control callback panicked on an incoming \
                 handshake — rejecting the connection"
            );
            -1
        }
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

/// `true` for every libsrt state from which no further I/O is possible.
///
/// **All four, not just `Broken | Closed`.** libsrt walks a dying socket
/// BROKEN → CLOSED → (GC removes it) → NONEXIST, and `garbageCollect` runs on
/// a 1 s cadence while `removeSocket` fires a tick after that — so
/// `srt_getsockstate` reports a reapable state for only ~2–3 s. The bridge
/// samples state on a throttled sweep, so it can easily observe the socket
/// only *after* that window, landing on `NonExist` (which is also the `_`
/// catch-all in `raw_state_to_status`). Treating that as non-terminal put the
/// socket in a dead zone: the send drain is gated on `Connected` so it is
/// never drained again, and the zombie reaper matched only `Broken | Closed`
/// so it was never reaped — leaving a Tokio-side `send()` parked on a full
/// channel **forever**, with no error and no recovery. That is bilbycast-edge
/// issue #100: an SRT caller output latched `idle` while its peer's listener
/// sat waiting, cured only by recreating the output.
pub(crate) fn is_terminal_status(status: SocketStatus) -> bool {
    matches!(
        status,
        SocketStatus::Broken | SocketStatus::Closing | SocketStatus::Closed | SocketStatus::NonExist
    )
}

fn update_status(state: &mut SocketState, status: SocketStatus) {
    let previous = state.last_status;
    state.last_status = status;
    if let Some(ref tx) = state.status_tx {
        let _ = tx.send(status);
    }
    // On terminal states, drop the recv_tx so the Tokio-side recv() unblocks
    // with ConnectionLost. Without this, callers hang forever on dead sockets
    // because the channel sender is still held by the I/O thread.
    if is_terminal_status(status) {
        state.recv_tx = None;
        // Same for the send side — but **only** for a socket that was
        // actually live. A freshly created group reports SRTS_BROKEN at
        // `RegisterSocket` time, before `ConnectGroup` has run and given it
        // any members (`CUDTGroup::getStatus` on a memberless group), so an
        // unguarded drop here would tear the channels off every bonded output
        // before it ever connected.
        if matches!(previous, SocketStatus::Connected | SocketStatus::Connecting) {
            state.send_rx = None;
        }
    }
}

fn cleanup(epoll_id: c_int, sockets: &mut HashMap<SocketId, SocketState>) {
    for (id, mut state) in sockets.drain() {
        // Close before dropping the state — see [`close_and_release`], which
        // this mirrors (the map is being drained, so it cannot be used here).
        // Made explicit rather than left to end-of-scope drop order, because an
        // `AccessControlSlot` freed ahead of `srt_close` is a use-after-free in
        // libsrt's accept hook.
        unsafe {
            srt_epoll_remove_usock(epoll_id, id);
            srt_close(id);
        }
        if let Some(reply) = state.connect_reply.take() {
            let _ = reply.send(Err(SrtError::SocketClosed));
        }
        drop(state);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The states libsrt walks a dying socket through, and the reason
    /// bilbycast-edge #100 latched: `Closing` and `NonExist` are just as
    /// terminal as `Broken`/`Closed`, but were treated as live.
    ///
    /// The window in which `srt_getsockstate` reports `Broken` or `Closed` is
    /// only ~2-3 s wide (`garbageCollect` runs on a 1 s cadence and
    /// `removeSocket` fires a tick after `checkBrokenSockets`), while the
    /// bridge samples state on a throttled sweep. Miss that window and the
    /// socket settles on `NonExist` — which is also `raw_state_to_status`'s
    /// `_` catch-all — where the send drain (gated on `Connected`) never runs
    /// again and the zombie reaper never fires, parking a Tokio-side `send()`
    /// on a full channel forever.
    #[test]
    fn every_non_live_state_is_terminal() {
        for status in [
            SocketStatus::Broken,
            SocketStatus::Closing,
            SocketStatus::Closed,
            SocketStatus::NonExist,
        ] {
            assert!(is_terminal_status(status), "{status:?} must be terminal");
        }
    }

    /// Anything a socket can legitimately be doing while still usable must
    /// stay non-terminal, or a healthy socket gets reaped mid-handshake.
    #[test]
    fn live_and_pre_connection_states_are_not_terminal() {
        for status in [
            SocketStatus::Init,
            SocketStatus::Opened,
            SocketStatus::Listening,
            SocketStatus::Connecting,
            SocketStatus::Connected,
        ] {
            assert!(!is_terminal_status(status), "{status:?} must not be terminal");
        }
    }

    /// `raw_state_to_status`'s catch-all maps unknown values to `NonExist`,
    /// so an unrecognised libsrt state must be terminal rather than silently
    /// treated as live — that is the fail-safe direction.
    #[test]
    fn unknown_raw_state_maps_to_a_terminal_status() {
        let unknown = raw_state_to_status(9999 as SRT_SOCKSTATUS);
        assert_eq!(unknown, SocketStatus::NonExist);
        assert!(is_terminal_status(unknown));
    }

    // ── Listener access control ────────────────────────────────────────
    //
    // These cover the two halves of the same defect:
    //   1. the hook was registered *after* `srt_listen`, which libsrt rejects
    //      silently, so no `AccessControl` ever ran — an SRT listener with a
    //      configured `stream_id` filter accepted every caller;
    //   2. the opaque pointer handed to libsrt was freed immediately after
    //      registration (`*Box::from_raw(..)` moves out of the box and
    //      deallocates it), so once (1) was fixed the trampoline would have
    //      read a fat pointer — data + vtable — out of freed heap.
    //
    // Half (1) can only be proved against a real listening socket, and
    // `srt_bind` starts libsrt worker threads whose teardown SIGSEGVs this
    // harness at exit. That half therefore lives in
    // `tests/listener_access_control.rs`, which owns its `main` and leaves via
    // `libc::_exit(0)`. Nothing below binds.

    use srt_protocol::error::RejectReason;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct StreamIdGate(&'static str);

    impl AccessControl for StreamIdGate {
        fn on_accept(&self, info: &HandshakeInfo) -> Result<(), RejectReason> {
            if info.stream_id == self.0 {
                Ok(())
            } else {
                Err(RejectReason::Peer)
            }
        }
    }

    struct Panicker;

    impl AccessControl for Panicker {
        fn on_accept(&self, _info: &HandshakeInfo) -> Result<(), RejectReason> {
            panic!("access-control policy blew up");
        }
    }

    /// Invoke the trampoline exactly the way libsrt does.
    fn call_trampoline(slot: &AccessControlSlot, peer: &str, stream_id: &str) -> c_int {
        let sa = socket_addr_to_sockaddr(&peer.parse().unwrap());
        let sid = CString::new(stream_id).unwrap();
        unsafe {
            listen_callback_trampoline(
                slot.opaque(),
                0,
                5,
                &sa as *const libc::sockaddr_storage as *const std::ffi::c_void as *const sockaddr,
                sid.as_ptr(),
            )
        }
    }

    /// The trampoline recovers the `AccessControl` by reading a fat pointer
    /// out of the opaque address libsrt was given. That address must still be
    /// a live allocation this process owns — which is exactly what the old
    /// `state.access_control = Some(*Box::from_raw(ac_ptr))` destroyed: it
    /// moved the inner box out and freed the outer allocation, leaving libsrt
    /// holding a dangling pointer to the vtable it would call through.
    #[test]
    fn trampoline_reads_the_access_control_through_the_registered_opaque() {
        let slot = AccessControlSlot::new(Box::new(StreamIdGate("letmein")));

        // 0 = accept, -1 = reject, per libsrt's `runAcceptHook`.
        assert_eq!(call_trampoline(&slot, "10.0.0.9:9000", "letmein"), 0);
        assert_eq!(call_trampoline(&slot, "10.0.0.9:9000", "not-it"), -1);
        assert_eq!(call_trampoline(&slot, "10.0.0.9:9000", ""), -1);

        // Still live after use: the slot owns the allocation, nothing else
        // freed it behind libsrt's back.
        assert_eq!(call_trampoline(&slot, "10.0.0.9:9000", "letmein"), 0);
    }

    /// A null opaque means no access control was configured — accept.
    #[test]
    fn trampoline_accepts_when_no_access_control_is_registered() {
        let sa = socket_addr_to_sockaddr(&"10.0.0.9:9000".parse().unwrap());
        let ret = unsafe {
            listen_callback_trampoline(
                std::ptr::null_mut(),
                0,
                5,
                &sa as *const libc::sockaddr_storage as *const std::ffi::c_void as *const sockaddr,
                std::ptr::null(),
            )
        };
        assert_eq!(ret, 0);
    }

    /// libsrt calls the trampoline from its receive-queue worker on an
    /// unauthenticated peer's handshake. Unwinding out of an `extern "C"` fn
    /// aborts the process, so a panicking policy would let a remote caller
    /// kill a live node. It must be caught, and it must fail *closed*.
    #[test]
    fn trampoline_rejects_instead_of_aborting_when_the_policy_panics() {
        let slot = AccessControlSlot::new(Box::new(Panicker));
        assert_eq!(call_trampoline(&slot, "10.0.0.9:9000", "anything"), -1);
    }

    /// The slot now owns the allocation libsrt points at, so ownership has to
    /// be exactly-once: no leak, no double free.
    #[test]
    fn access_control_slot_frees_its_payload_exactly_once() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);

        struct Counted;

        impl AccessControl for Counted {
            fn on_accept(&self, _info: &HandshakeInfo) -> Result<(), RejectReason> {
                Ok(())
            }
        }

        impl Drop for Counted {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        let slot = AccessControlSlot::new(Box::new(Counted));
        assert_eq!(DROPS.load(Ordering::SeqCst), 0, "freed while registered");
        assert_eq!(call_trampoline(&slot, "10.0.0.9:9000", ""), 0);
        assert_eq!(DROPS.load(Ordering::SeqCst), 0, "freed while registered");
        drop(slot);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1, "leaked or double-freed");
    }

    /// A `Listen` that refuses to listen must not keep the socket.
    ///
    /// The arming failure is fail-closed by design, so this branch is *meant*
    /// to be taken — which makes leaking there expensive. The only sender of
    /// `Listen` is `SrtListenerBuilder::bind`, which propagates the error
    /// before an `SrtListener` exists, and `SrtListener::drop` is the only
    /// thing that ever sends `Close`; `cleanup_zombies` skips listeners. So a
    /// socket left in the map here is unreachable forever, and since it is
    /// already `srt_bind`ed, libsrt holds its UDP port for the life of the
    /// process. In bilbycast-edge, where listener binds are retried, that
    /// turns one arming failure into a permanently dead ingress port reported
    /// as somebody else's `port_conflict`.
    ///
    /// Uses a socket id libsrt has already disposed of, which is the one way
    /// to make `srt_listen_callback` fail without a network: `locateSocket`
    /// misses and the install returns `SRT_ERROR`. No `srt_bind` happens here,
    /// so this test starts none of the libsrt worker threads whose teardown
    /// forces the `tests/listener_access_control.rs` target to exist.
    #[test]
    fn listen_releases_the_socket_when_the_access_control_hook_cannot_be_armed() {
        libsrt_sys::ensure_initialized();
        let epoll_id = unsafe { srt_epoll_create() };
        assert!(epoll_id >= 0, "srt_epoll_create failed");

        // A socket id that libsrt no longer knows about.
        let id = unsafe { srt_create_socket() };
        assert!(id >= 0, "srt_create_socket failed");
        assert_eq!(unsafe { srt_close(id) }, 0, "srt_close failed");

        let mut sockets: HashMap<SocketId, SocketState> = HashMap::new();
        let (accept_tx, _accept_rx) = mpsc::channel(4);
        process_command(
            IoCommand::RegisterListener {
                id,
                accept_tx,
                access_control: Some(Box::new(StreamIdGate("letmein"))),
            },
            epoll_id,
            &mut sockets,
        );

        // Pin the precondition: this test is only meaningful if it is the
        // *arming* that fails, not `srt_listen`.
        assert!(
            register_listen_callback(id, &sockets).is_err(),
            "libsrt installed an accept hook on a disposed socket — this test \
             is no longer exercising the fail-closed arming branch",
        );

        let (tx, mut rx) = oneshot::channel();
        process_command(IoCommand::Listen { id, backlog: 5, reply: tx }, epoll_id, &mut sockets);
        assert!(
            rx.try_recv().expect("no reply").is_err(),
            "Listen reported success while its access-control policy could not \
             be armed — the listener would be silently open",
        );
        assert!(
            !sockets.contains_key(&id),
            "fail-closed Listen left the socket registered: nothing can ever \
             close it, so its bound UDP port is held for the life of the process",
        );

        unsafe { srt_epoll_release(epoll_id) };
    }
}
