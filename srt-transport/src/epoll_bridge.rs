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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

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
use crate::group::{GroupEndpoint, MAX_GROUP_MEMBER_WEIGHT};

/// Opaque identifier for sockets managed by the I/O thread.
pub(crate) type SocketId = i32; // SRTSOCKET is i32

/// Maximum receive buffer size for a single srt_recvmsg2 call.
const RECV_BUF_SIZE: usize = 65536;

/// Maximum epoll events per wait call.
const MAX_EPOLL_EVENTS: usize = 64;

/// How often every live group is read whether or not libsrt raised its
/// read-readiness.
///
/// libsrt can leave a group's due packets with no readiness raised. A
/// member's TSBPD thread releases its receive lock to tell the group a
/// packet is due (`CUDTGroup::updateReadState`, behind an `InvertedLock` in
/// vendored `srtcore/core.cpp`, `CUDT::tsbpd`). A group read that lands in
/// that window takes the packet — from this member, whose wake-up then
/// reaches a thread that is not waiting, or from another member, discarding
/// this one's copy with no wake-up at all — and the TSBPD thread, back from
/// the group, sleeps with no deadline. Only new data on that member (its
/// ACK) or a read from it wakes it again. Mid-stream the next ACK comes
/// within about 10 ms; when the sender pauses or stops, the packets inside
/// the latency window stay in the members' buffers until it resumes, or for
/// good — the last ~10 messages of a stream that ends. A read finds them
/// (`CUDTGroup::recv` checks each member's buffer against the clock itself)
/// and, finding nothing more, restarts the member's TSBPD thread.
///
/// The sweep also recovers a readiness libsrt clears without a read:
/// `srt_connect_group` on a group with a latched ERR clears IN and OUT with
/// it (vendored `srtcore/api.cpp:1501-1511`), and the bridge connects into a
/// live group whenever a member is re-added or replaced
/// ([`check_stranded_members`]).
///
/// And it is the only reader of a readiness [`handle_recv`] declined: an IN
/// edge that arrives while libsrt reads the group as not `SRTS_CONNECTED`
/// (its only up member just broke, say, and a re-added one is still
/// connecting) is left set, because only `CUDTGroup::recv` clears it, so no
/// further edge fires for it once the group is connected again. Without the
/// sweep that is the permanent stall the `SRTO_RCVDATA` gate used to cause.
const GROUP_RECV_SWEEP: Duration = Duration::from_millis(100);

// ── Members libsrt strands at connect ──
//
// See [`check_stranded_members`] for the defect and the repair.

/// How often the bridge looks at the group members it is watching. A member
/// is watched only until it is up — about a second after it is spawned —
/// except a backup group's receiving member, looked at once a second
/// ([`Verdict::Masked`]); nothing runs per packet.
const STRANDED_CHECK: Duration = Duration::from_millis(100);

/// How long a member must keep reading stranded before it is replaced.
///
/// One reading is already final (see [`classify_watched`]); this is cheap
/// insurance against a gap in that reasoning or a libsrt bump that changes
/// it, and stays well inside bilbycast-edge's first supervisor tick (1 s)
/// and its `degrade_after` (at least 5 s).
const STRANDED_MEMBER_GRACE: Duration = Duration::from_millis(500);

/// How many times one member is replaced, counting a replacement's own
/// replacement. Past it the stranded member is only closed, and re-adding
/// it is left to the application (bilbycast-edge's supervisor, with its
/// backoff), so a host where the race is somehow deterministic cannot spin.
const MAX_STRANDED_REPAIRS: u8 = 3;

/// Added to a member's own connect timeout (`SRTO_CONNTIMEO`) to give the
/// moment by which libsrt must have resolved its handshake. libsrt fails a
/// caller member whose handshake outlives that timeout
/// (`CRendezvousQueue::updateConnStatus` → `completeBrokenConnectionDependencies`,
/// vendored `srtcore/queue.cpp:1025-1041`, `srtcore/core.cpp:12360-12419`),
/// so one still unresolved after it is stuck in a way the live-state
/// reading did not catch, and is replaced too.
const HANDSHAKE_TTL_SLACK: Duration = Duration::from_secs(1);

/// The connect timeout assumed when a member's own cannot be read: libsrt's
/// default `SRTO_CONNTIMEO`.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// How often a backup-mode member whose receive state hides its send state
/// is looked at again. See [`Verdict::Masked`].
const MASKED_MEMBER_RECHECK: Duration = Duration::from_secs(1);

/// Added to the member's latency before a member its replacement superseded
/// is closed. See [`superseded_linger`].
const SUPERSEDED_LINGER_SLACK: Duration = Duration::from_secs(1);

/// Watched members the bridge has replaced or closed, process wide: every
/// one [`check_stranded_members`] acted on, which is a member listed Pending
/// (or `CONNECTING`) on a connected socket, one listed Broken on a connected
/// socket, or one still unresolved past its connect timeout with a socket
/// that is not dead. Members marked stranded by the test hook
/// (`IoCommand::TestStrandMember`) are not counted, so the number says how
/// often libsrt really did one of these.
static STRANDED_REPAIRS: AtomicU64 = AtomicU64::new(0);

/// See [`STRANDED_REPAIRS`].
pub(crate) fn stranded_member_repairs() -> u64 {
    STRANDED_REPAIRS.load(Ordering::Relaxed)
}

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
        endpoints: Vec<GroupEndpoint>,
        reply: oneshot::Sender<Result<(), SrtError>>,
    },
    /// Connect one more member into a live group (re-adding a member libsrt
    /// removed as broken). Refused unless the group still has a live member;
    /// see [`add_group_member`].
    AddGroupMember {
        id: SocketId,
        endpoint: GroupEndpoint,
        reply: oneshot::Sender<Result<(), SrtError>>,
    },
    /// Test hook: treat the healthy member carrying `endpoint.token` as if
    /// libsrt had stranded it, so [`check_stranded_members`] replaces it with
    /// `endpoint`. Exercises the real close / re-add against libsrt; it does
    /// not exercise libsrt's own overwrite, which only a patched libsrt can
    /// force. `InvalidParam` when no such member is listed. Only in builds
    /// with the `test-hooks` feature, which this crate's own tests enable.
    #[cfg(feature = "test-hooks")]
    TestStrandMember {
        id: SocketId,
        endpoint: GroupEndpoint,
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
    /// Whether this is a backup-mode group (`CreateGroup` only).
    backup: bool,
    /// Last known status.
    last_status: SocketStatus,
    /// Pending connect reply (for async connect).
    connect_reply: Option<oneshot::Sender<Result<(), SrtError>>>,
    /// Members this bridge spawned into this caller group whose handshake it
    /// is still watching for libsrt stranding them. Empty for everything
    /// else, including a listener's mirror group. See
    /// [`check_stranded_members`].
    watched: Vec<WatchedMember>,
}

/// One group member the bridge spawned (`srt_connect_group`) and is still
/// watching. See [`check_stranded_members`].
#[derive(Debug, Clone)]
struct WatchedMember {
    id: SocketId,
    /// What it was connected with, so a replacement uses exactly the same
    /// target, source, weight and token.
    endpoint: GroupEndpoint,
    /// Its socket's own state, read at the start of each check **before**
    /// the group listing. Scratch, not history; `Init` for a member spawned
    /// in the current check, which counts as still handshaking.
    live: SocketStatus,
    /// Not looked at before this.
    not_before: Instant,
    /// libsrt has connected or failed a member by now: spawn + its connect
    /// timeout + [`HANDSHAKE_TTL_SLACK`].
    resolve_by: Instant,
    /// First of the current run of stranded readings.
    stranded_since: Option<Instant>,
    /// How many replacements stand behind this one (0 = spawned for the
    /// application).
    repairs: u8,
    /// Stranded members this one replaces that were the only members up at
    /// the peer ([`RepairPlan::SpawnThenClose`], [`RepairPlan::HandToSibling`]).
    /// They stay in the group until this one is up and has been for
    /// [`superseded_linger`], so the peer's mirror group is never emptied;
    /// closed then, or as soon as this one fails.
    supersedes: Vec<SocketId>,
    /// When `supersedes` is closed, once this member is up.
    close_superseded_at: Option<Instant>,
    /// Set by the test hook (`IoCommand::TestStrandMember`): read as
    /// stranded. Never set in a build without the `test-hooks` feature.
    forced: bool,
    /// Its replacement has been put off for another member's handshake
    /// ([`RepairPlan::Wait`]), and that has been logged.
    waiting: bool,
}

impl WatchedMember {
    fn new(id: SocketId, endpoint: GroupEndpoint, resolve_by: Instant, now: Instant) -> Self {
        Self {
            id,
            endpoint,
            live: SocketStatus::Init,
            not_before: now,
            resolve_by,
            stranded_since: None,
            repairs: 0,
            supersedes: Vec::new(),
            close_superseded_at: None,
            forced: false,
            waiting: false,
        }
    }

    /// Watch a member just spawned into a group: its handshake has until
    /// its own connect timeout, plus slack, to resolve.
    fn spawned(id: SocketId, endpoint: GroupEndpoint, now: Instant) -> Self {
        Self::new(id, endpoint, now + connect_timeout_of(id) + HANDSHAKE_TTL_SLACK, now)
    }
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
    let mut last_group_sweep = Instant::now();
    let mut last_stranded_check = Instant::now();
    // Reused for every group listing the stranded-member check reads.
    let mut group_rows: Vec<SRT_SOCKGROUPDATA> = Vec::new();

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

        // Read every live group on a timer as well as on IN: libsrt can
        // leave a group's readiness unraised. See `GROUP_RECV_SWEEP`.
        if has_connected && last_group_sweep.elapsed() >= GROUP_RECV_SWEEP {
            last_group_sweep = Instant::now();
            sock_id_buf.clear();
            sock_id_buf.extend(
                sockets
                    .iter()
                    .filter(|(id, s)| {
                        is_group_id(**id)
                            && s.last_status == SocketStatus::Connected
                            && s.recv_tx.as_ref().is_some_and(|tx| !tx.is_closed())
                    })
                    .map(|(id, _)| *id),
            );
            for id in sock_id_buf.iter().copied() {
                handle_recv(id, &mut sockets, &mut recv_buf);
            }
        }

        // Replace members libsrt stranded at connect. Not gated on
        // `has_connected`: the state poll can hold a group at Connecting
        // while its members handshake. See `check_stranded_members`.
        if last_stranded_check.elapsed() >= STRANDED_CHECK {
            last_stranded_check = Instant::now();
            check_stranded_members(&mut sockets, &mut group_rows, &mut sock_id_buf);
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
                    // A group is `Init` from `RegisterSocket` until
                    // `ConnectGroup` gives it members, and libsrt reads a
                    // memberless group as BROKEN — see `RegisterSocket`.
                    if state.is_group && state.last_status == SocketStatus::Init {
                        continue;
                    }
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
        // Read the flags as the enum's own alias type rather than a fixed
        // width: `SRT_EPOLL_OPT` is `c_uint` under GCC/Clang but `c_int`
        // under MSVC, so the constants below then need no per-target cast.
        let ev = event.events as SRT_EPOLL_OPT;

        // Listener accept
        if let Some(state) = sockets.get(&sock_id) {
            if state.is_listener && (ev & SRT_EPOLL_IN) != 0 {
                handle_accept(sock_id, epoll_id, sockets);
                continue;
            }
        }

        // Connect completion
        if (ev & SRT_EPOLL_CONNECT) != 0 {
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
        if (ev & SRT_EPOLL_IN) != 0 {
            handle_recv(sock_id, sockets, recv_buf);
        }

        // Writable — drain send queue
        if (ev & SRT_EPOLL_OUT) != 0 {
            handle_send(sock_id, sockets);
        }

        // Errors
        if (ev & SRT_EPOLL_ERR) != 0 {
            if let Some(state) = sockets.get_mut(&sock_id) {
                if state.is_group && !group_err_is_real(sock_id) {
                    continue;
                }
                update_status(state, SocketStatus::Broken);
            }
        }
    }
}

/// Whether an `SRT_EPOLL_ERR` reported on a **group** means the group has
/// failed, judged by the group's own status.
///
/// libsrt raises ERR readiness on a group that has not failed: adding a
/// group to an epoll (`CUDTGroup::addEPoll`) sets ERR when no member is
/// "non-broken", and it tests that with `CUDTSocket::broken()`, which is
/// `m_bBroken || !m_bConnected` — true for a member whose handshake is
/// merely still running. `ConnectGroup` adds the group to the bridge's
/// epoll straight after the non-blocking `srt_connect_group`, when every
/// member is necessarily still connecting, so every caller group was handed
/// an ERR at birth: the bridge marked it `Broken`, dropped both channels,
/// and a bonded caller never carried a packet — each connect ended at once
/// in a send or receive `ConnectionLost` and a redial.
///
/// `getStatus` is the group's real state: `SRTS_CONNECTED` while any member
/// is Idle or Running; otherwise the live socket state of the *first*
/// listed Pending member (vendored `srtcore/group.cpp:962-1019`) — which is
/// `SRTS_CONNECTED` too for a member libsrt stranded at connect (see
/// [`check_stranded_members`]); `SRTS_BROKEN` when none is left. A genuine
/// all-links-down ERR agrees with it; one that does not is ignored, and the
/// bridge's periodic state poll still reads `getStatus` and tears the group
/// down within about a second if it does fail later.
fn group_err_is_real(group: SocketId) -> bool {
    is_terminal_status(raw_state_to_status(unsafe { srt_getsockstate(group) }))
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
        let tokio_side_gone = state.recv_tx.as_ref().is_none_or(|tx| tx.is_closed());
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
                backup: false,
                last_status: SocketStatus::Init,
                connect_reply: None,
                watched: Vec::new(),
            });
            state.recv_tx = Some(recv_tx);
            state.send_rx = Some(send_rx);
            state.status_tx = Some(status_tx);

            // Query actual libsrt state — accepted sockets are already Connected
            // but or_insert_with defaults to Init. Correct it here so the send
            // loop drains data immediately instead of waiting for the next
            // STATE_POLL_INTERVAL cycle.
            //
            // Not for a group (`CreateGroup` registered it first, so
            // `is_group` is already set): it is registered *before*
            // `ConnectGroup` gives it any members, and libsrt reports a
            // memberless group as `SRTS_BROKEN`. Applying that here dropped
            // `recv_tx`, so a bonded caller's `recv` failed before it was
            // ever connected. A group's status starts at `ConnectGroup`.
            if !state.is_group {
                let raw_state = unsafe { srt_getsockstate(id) };
                let actual_status = raw_state_to_status(raw_state);
                if actual_status != state.last_status {
                    update_status(state, actual_status);
                }
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
                backup: false,
                last_status: SocketStatus::Init,
                connect_reply: None,
                watched: Vec::new(),
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
                    backup: mode == SRT_GTYPE_BACKUP,
                    last_status: SocketStatus::Init,
                    connect_reply: None,
                    watched: Vec::new(),
                };
                sockets.insert(grp, state);
                let _ = reply.send(Ok(grp));
            }
        }

        IoCommand::ConnectGroup { id, endpoints, reply } => {
            let spawned = connect_group(id, &endpoints);
            if let Some(err) = spawned.refused {
                let _ = reply.send(Err(err));
                return true;
            }
            add_to_epoll(
                epoll_id,
                id,
                SRT_EPOLL_IN as c_int | SRT_EPOLL_ERR as c_int
                    | SRT_EPOLL_ET as c_int,
            );
            if let Some(state) = sockets.get_mut(&id) {
                update_status(state, SocketStatus::Connected);
                // Only a group `CreateGroup` made is a caller group; see
                // `check_stranded_members` for why that is required.
                if state.is_group {
                    let now = Instant::now();
                    for (ep, member) in endpoints.iter().zip(&spawned.members) {
                        if let Ok(member) = member {
                            state.watched.push(WatchedMember::spawned(*member, *ep, now));
                        }
                    }
                }
            }
            let _ = reply.send(Ok(()));
        }

        IoCommand::AddGroupMember { id, endpoint, reply } => {
            let _ = reply.send(add_group_member(id, &endpoint, sockets));
        }

        #[cfg(feature = "test-hooks")]
        IoCommand::TestStrandMember { id, endpoint, reply } => {
            let _ = reply.send(force_stranded(id, endpoint, sockets));
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
/// synchronously (paths in the vendored libsrt v1.5.7):
///   * `CUDTUnited::close` takes the `SRTS_LISTENING` branch and calls
///     `notListening()` before returning (api.cpp:2172-2195);
///   * `notListening()` calls `CRcvQueue::removeListener()`
///     (core.h:585-589);
///   * `removeListener` is `m_pListener.compare_exchange(u, NULL)`, which takes
///     an EXCLUSIVE lock on the queue's listener slot (queue.cpp:1765-1768,
///     sync.h `CSharedObjectPtr`);
///   * the receive-queue worker holds a SHARED lock on that same slot across
///     the whole of `processConnectRequest` → `newConnection` →
///     `runAcceptHook` → [`listen_callback_trampoline`] (queue.cpp:1456-1474).
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
///
/// A group still at `Init` is not unsubscribed first: a group joins the
/// epoll only when `ConnectGroup` succeeds, which also moves it off `Init`
/// (the state poll skips a group at `Init`, so nothing else does). That is
/// the group `SrtGroupBuilder::connect` closes when its connect spawned no
/// member, and libsrt logs unsubscribing it as an internal error at Error
/// level ("IPE: … NOT SUBSCRIBED"), once per failed attempt of a retrying
/// caller.
fn close_and_release(
    epoll_id: c_int,
    id: SocketId,
    sockets: &mut HashMap<SocketId, SocketState>,
) -> Option<SocketState> {
    let never_polled = sockets
        .get(&id)
        .is_some_and(|s| s.is_group && s.last_status == SocketStatus::Init);
    if !never_polled {
        unsafe { srt_epoll_remove_usock(epoll_id, id) };
    }
    unsafe { srt_close(id) };
    sockets.remove(&id)
}

/// libsrt's group-id bit (`SRTGROUP_MASK`, vendored `srtcore/srt.h:141`),
/// which libsrt itself tests to tell a group from a socket. bindgen does not
/// emit it: it is a `static const` in the header, not a macro or an enum.
const SRTGROUP_MASK: SocketId = 1 << 30;

/// Whether `id` names a socket group: a caller group from `CreateGroup`, or
/// a listener's mirror group handed out by `srt_accept` on a `group_connect`
/// listener (registered by `RegisterSocket` like any accepted socket, so its
/// `SocketState::is_group` is false — hence the id test).
fn is_group_id(id: SocketId) -> bool {
    id >= 0 && id & SRTGROUP_MASK != 0
}

/// Drain every message libsrt will hand over now.
///
/// For a single socket, `SRTO_RCVDATA` is checked before each
/// `srt_recvmsg2` call to avoid libsrt's "no data" exception path
/// (`EASYNCRCV`): C++ stack unwinding is expensive (~98% of srt-io CPU in
/// profiling), so a socket's buffer is not read once it reports empty.
///
/// **A group is read until `srt_recvmsg2` fails, with no such check.**
/// `SRTO_RCVDATA` on a group id is not the group's: `CUDTGroup::getOpt`
/// answers it from the group's *first listed member* (vendored
/// `srtcore/group.cpp`, "Return the value from the first member socket"),
/// and members are listed in the order they joined. When that member is
/// the one that went dark — the link a bonded receiver exists to survive —
/// it reads 0 while the live member's buffer fills. Stopping there was not
/// a skipped read but a permanent stall: a group's read-readiness is
/// edge-triggered here, and libsrt clears it only inside `CUDTGroup::recv`
/// (when it finds nothing readable, or after a read that leaves no member
/// ready), so a set readiness that is never read never produces another
/// edge. The receiver went silent for the rest of the connection.
///
/// The cost is the exception this check was avoiding, once per drain. It
/// was already being paid: `SRTO_RCVDATA` counts every contiguous packet,
/// including those still waiting out the TSBPD latency (`CRcvBuffer::
/// getRcvDataSize`), so on a live group it was nearly always non-zero and
/// each drain already ended in an `EASYNCRCV` from `srt_recvmsg2`.
///
/// A group libsrt does not report `SRTS_CONNECTED` is not read: its
/// readiness at that point is libsrt waking pollers on a dying group, and
/// `CUDTGroup::recv` on a group that has lost every member logs an
/// Error-level "ABANDONING" line rather than just failing. That status is
/// `CONNECTED` while some member is Idle or Running — and also while the
/// first Pending member's own socket is connected, which is a member libsrt
/// stranded at connect. A group whose only connected member is one of those
/// is still read. libsrt reads that member like any other when it listed it
/// `CONNECTED`; when it listed it `CONNECTING`, group receive skips it
/// (vendored `srtcore/group.cpp:2108-2112`), finds no member to read and
/// logs "ALL LINKS BROKEN, ABANDONING" (`:2428-2432`) on each read until
/// [`check_stranded_members`] has replaced the member (about a second).
///
/// A readiness this declines stays set, so libsrt raises no new edge for
/// it; [`GROUP_RECV_SWEEP`] is what reads the group once it is connected
/// again.
fn handle_recv(
    sock_id: SocketId,
    sockets: &mut HashMap<SocketId, SocketState>,
    recv_buf: &mut [u8],
) {
    let group = is_group_id(sock_id);
    if group && unsafe { srt_getsockstate(sock_id) } != SRTS_CONNECTED {
        return;
    }
    loop {
        if !group {
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
            break; // Nothing more now (EASYNCRCV), or the socket failed
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
/// m_bListening || m_bBroken) throw` — vendored `srtcore/core.h:1176-1182`),
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

/// Build libsrt's per-member connect record for one [`GroupEndpoint`]:
/// target, optional source, weight and token.
///
/// `srt_prepare_endpoint` copies `namelen` bytes from both the source and the
/// target (vendored `srtcore/srt_c_api.cpp`), so both are passed as full
/// `sockaddr_storage`. With no source it zeroes the source and gives it the
/// target's family, which libsrt reads as "do not bind".
fn prepare_target(ep: &GroupEndpoint) -> SRT_SOCKGROUPCONFIG {
    let dst = socket_addr_to_sockaddr(&ep.addr);
    let src = ep.local_addr.as_ref().map(socket_addr_to_sockaddr);
    let src_ptr = src.as_ref().map_or(std::ptr::null(), |sa| {
        sa as *const libc::sockaddr_storage as *const std::ffi::c_void as *const sockaddr
    });
    let mut target = unsafe {
        srt_prepare_endpoint(
            src_ptr,
            &dst as *const libc::sockaddr_storage as *const std::ffi::c_void as *const _,
            std::mem::size_of::<libc::sockaddr_storage>() as c_int,
        )
    };
    target.weight = ep.weight.min(MAX_GROUP_MEMBER_WEIGHT);
    target.token = ep.token;
    target
}

/// What one `srt_connect_group` call left in the group.
struct GroupConnect {
    /// `Some` when libsrt refused the call as a whole: no member it counts
    /// as spawned. When no member could be spawned, libsrt reports a generic
    /// `CONNLOST`; the first per-member error code is used instead when
    /// there is one, so a bind failure on a member's source reads as itself.
    refused: Option<SrtError>,
    /// Per endpoint, in order: `Ok(member id)` for a member now in the group
    /// (its handshake continues in the background), `Err` for one that is
    /// not.
    members: Vec<Result<SocketId, SrtError>>,
}

impl GroupConnect {
    /// The single member an [`add_group_member`] or a replacement spawned.
    fn single(self) -> Result<SocketId, SrtError> {
        match (self.members.into_iter().next(), self.refused) {
            (Some(Ok(member)), _) => Ok(member),
            (_, Some(err)) | (Some(Err(err)), None) => Err(err),
            (None, None) => Err(SrtError::ConnectionLost),
        }
    }
}

/// Connect `endpoints` into group `grp`, one libsrt member each.
///
/// A member libsrt reports as failed but **keeps in the group** is returned
/// as spawned. `groupConnect` reads a member's status straight after
/// starting its handshake and, finding `SRTS_BROKEN`, lists the member
/// Broken and reports no id for it (vendored `srtcore/api.cpp:1813-1818`) —
/// but `CUDTSocket::getStatus` also reads BROKEN for an instant in the
/// middle of a *successful* handshake (`m_bConnecting` already false,
/// `m_bConnected` not yet true: `srtcore/core.cpp:5106-5118`,
/// `srtcore/api.cpp:108-123`). Such a member ends Idle (libsrt's own write
/// came second) or listed Broken on a connected socket, which a receive-only
/// group never closes. Either way it is in the group, so it is reported and
/// watched like any spawned member ([`check_stranded_members`]). Found by
/// listing the group before and after the call.
fn connect_group(grp: SocketId, endpoints: &[GroupEndpoint]) -> GroupConnect {
    if endpoints.is_empty() {
        return GroupConnect { refused: Some(SrtError::InvalidParam), members: Vec::new() };
    }

    let mut rows = Vec::new();
    read_group_rows(grp, &mut rows);
    let before: Vec<SocketId> = rows.iter().map(|r| r.id).collect();

    let mut targets: Vec<SRT_SOCKGROUPCONFIG> = endpoints.iter().map(prepare_target).collect();

    let ret = unsafe {
        srt_connect_group(
            grp,
            targets.as_mut_ptr(),
            targets.len() as c_int,
        )
    };

    // Read libsrt's thread-local error before anything else can touch it.
    let refused = (ret < 0).then(|| {
        let call_error = last_srt_error();
        targets
            .iter()
            .find(|t| t.errorcode != 0)
            .map_or(call_error, |t| SrtError::from_code(t.errorcode))
    });

    let mut members: Vec<Result<SocketId, SrtError>> = targets
        .iter()
        .map(|t| {
            if t.id >= 0 && t.errorcode == 0 {
                Ok(t.id)
            } else if t.errorcode != 0 {
                Err(SrtError::from_code(t.errorcode))
            } else {
                Err(SrtError::ConnectionLost)
            }
        })
        .collect();

    // No id and no error code: libsrt found the member BROKEN after starting
    // it, but may have kept it. Claim each new listed member once.
    if targets.iter().any(|t| t.id < 0 && t.errorcode == 0) {
        read_group_rows(grp, &mut rows);
        let mut claimed: Vec<SocketId> = members.iter().filter_map(|m| m.as_ref().ok().copied()).collect();
        for (t, member) in targets.iter().zip(members.iter_mut()) {
            if t.id >= 0 || t.errorcode != 0 {
                continue;
            }
            let kept = rows
                .iter()
                .find(|r| r.token == t.token && !before.contains(&r.id) && !claimed.contains(&r.id))
                .map(|r| r.id);
            if let Some(kept) = kept {
                tracing::debug!(
                    "srt-io: group {} member @{} (token {}) was reported failed by libsrt \
                     but kept in the group; watching it",
                    grp,
                    kept,
                    t.token,
                );
                claimed.push(kept);
                *member = Ok(kept);
            }
        }
    }

    for (ep, result) in endpoints.iter().zip(&members) {
        if let Err(e) = result {
            tracing::warn!(
                "srt-io: group {} member {} (token {}, source {:?}) was not spawned: {:?}",
                grp,
                ep.addr,
                ep.token,
                ep.local_addr,
                e,
            );
        }
    }
    GroupConnect { refused, members }
}

/// Connect one member into a live group, and watch it
/// ([`check_stranded_members`]).
///
/// **Refused unless the group has at least one Idle or Running member**, read
/// here on the I/O thread right before `srt_connect_group`. libsrt's own
/// test for a failed group (`CUDTGroup::updateFailedLink`) counts a
/// *pending* member as healthy, and `getStatus` then reports that pending
/// member's `CONNECTING` rather than `BROKEN`. A member added once every live
/// link is gone would therefore keep the group from ever reaching a terminal
/// state while its handshake runs: the bridge would not tear it down, the
/// Tokio side would not see the loss and redial the group whole, and the
/// send drain (gated on `Connected`) would stall with the send channel
/// filling behind it. `srt_getsockstate` on a group is `getStatus`, which is
/// `SRTS_CONNECTED` when some member is Idle or Running — and also when the
/// only connected member is one libsrt stranded at connect, whose own
/// socket is connected; the bridge replaces that member within about a
/// second, so the add is let through and joins the repair.
///
/// The remaining window — the last live member breaks between this check
/// and the connect — is bounded by one connect timeout: the new member
/// either connects (the group recovers in place) or fails, and the bridge's
/// state poll then sees the group `BROKEN`.
///
/// **A no-op (`Ok`) while a member with the same token is already pending
/// or live** on a socket that is not dead: one handshake per endpoint. A
/// caller re-adds from a listing it read a moment earlier, and in between
/// the bridge may have replaced a stranded member with that very token;
/// spawning a second would leave two members carrying one endpoint for the
/// life of the group.
///
/// Also refused for a group the bridge no longer tracks or has already seen
/// break, so a group whose Tokio side is gone is never revived. Makes no
/// epoll or status change: the group is already registered.
fn add_group_member(
    id: SocketId,
    endpoint: &GroupEndpoint,
    sockets: &mut HashMap<SocketId, SocketState>,
) -> Result<(), SrtError> {
    let Some(state) = sockets
        .get_mut(&id)
        .filter(|s| s.is_group && !is_terminal_status(s.last_status))
    else {
        return Err(SrtError::ConnectionLost);
    };
    if unsafe { srt_getsockstate(id) } != SRTS_CONNECTED {
        return Err(SrtError::ConnectionLost);
    }
    let mut rows = Vec::new();
    read_group_rows(id, &mut rows);
    if let Some(existing) = member_in_flight(&rows, endpoint.token, &[]) {
        tracing::debug!(
            "srt-io: group {} already has member @{} for token {}; not adding another",
            id,
            existing,
            endpoint.token,
        );
        return Ok(());
    }
    let member = connect_group(id, std::slice::from_ref(endpoint)).single()?;
    state.watched.push(WatchedMember::spawned(member, *endpoint, Instant::now()));
    Ok(())
}

/// Fill `buf` with group `grp`'s member listing (`srt_group_data`), reusing
/// its allocation. Empty when the group is gone or has no member.
fn read_group_rows(grp: SocketId, buf: &mut Vec<SRT_SOCKGROUPDATA>) {
    if buf.len() < 8 {
        buf.resize(8, unsafe { std::mem::zeroed() });
    }
    let mut count = buf.len();
    let mut ret = unsafe { srt_group_data(grp, buf.as_mut_ptr(), &mut count) };
    // Too small: libsrt has written the size it needs into `count`.
    if ret < 0 && count > buf.len() {
        buf.resize(count, unsafe { std::mem::zeroed() });
        count = buf.len();
        ret = unsafe { srt_group_data(grp, buf.as_mut_ptr(), &mut count) };
    }
    if ret < 0 {
        count = 0;
    }
    buf.truncate(count);
}

/// A member's `SRTO_CONNTIMEO`, or libsrt's default when it cannot be read.
fn connect_timeout_of(member: SocketId) -> Duration {
    let mut ms: c_int = 0;
    let mut len = std::mem::size_of::<c_int>() as c_int;
    let ret = unsafe {
        srt_getsockflag(member, SRTO_CONNTIMEO, &mut ms as *mut c_int as *mut std::ffi::c_void, &mut len)
    };
    if ret < 0 || ms <= 0 {
        DEFAULT_CONNECT_TIMEOUT
    } else {
        Duration::from_millis(ms as u64)
    }
}

/// How long the members a replacement superseded stay in the group once the
/// replacement is up: the longer of the two directions' latencies on it,
/// plus [`SUPERSEDED_LINGER_SLACK`].
///
/// A stranded member carries nothing, but one that data reached after it
/// was last read, or one the test hook (`IoCommand::TestStrandMember`)
/// marked, can hold packets the replacement never carried: those sent
/// before the replacement was first used. Closing it breaks its peer at
/// once, discarding what that peer still holds inside its latency window,
/// and discards what this end holds. With no other member up nothing else
/// holds a copy, so the latency is waited out first.
fn superseded_linger(member: SocketId) -> Duration {
    let latency = |opt: SRT_SOCKOPT| {
        let mut ms: i32 = 0;
        let mut len = std::mem::size_of::<i32>() as c_int;
        let ret = unsafe {
            srt_getsockflag(member, opt, &mut ms as *mut i32 as *mut std::ffi::c_void, &mut len)
        };
        if ret < 0 { 0 } else { ms.max(0) as u64 }
    };
    Duration::from_millis(latency(SRTO_RCVLATENCY).max(latency(SRTO_PEERLATENCY))) + SUPERSEDED_LINGER_SLACK
}

/// Pending, Idle or Running, on a socket that is not dead: a member that
/// carries, or is about to carry, its endpoint.
fn in_flight(member: MemberStatus, live: SocketStatus) -> bool {
    matches!(member, MemberStatus::Pending | MemberStatus::Idle | MemberStatus::Running)
        && !is_terminal_status(live)
}

/// A listed member carrying `token`, other than those in `exclude`, that is
/// [`in_flight`].
fn member_in_flight(rows: &[SRT_SOCKGROUPDATA], token: i32, exclude: &[SocketId]) -> Option<SocketId> {
    rows.iter()
        .filter(|r| r.token == token && !exclude.contains(&r.id))
        .find(|r| {
            let live = raw_state_to_status(unsafe { srt_getsockstate(r.id) });
            in_flight(map_member_status(r.memberstate), live)
        })
        .map(|r| r.id)
}

/// What one look at a watched member found. See [`classify_watched`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Not listed, or listed Broken on a socket that is not connected:
    /// libsrt failed it, or it was closed.
    Gone,
    /// Listed Broken on a connected socket: libsrt will never use it again,
    /// and a receive-only group never closes it.
    BrokenLive,
    /// Its handshake finished, but libsrt will never send on it (or, listed
    /// `CONNECTING`, never read from it either).
    Stranded,
    /// Up: libsrt sends on it.
    Confirmed,
    /// Running in a backup group, on a connected socket. libsrt lists a
    /// member Running when *either* direction runs (`copyGroupData`,
    /// vendored `srtcore/group.cpp:1982`), so data received on it hides its
    /// send state; and in backup mode a keepalive turns the receive state
    /// back to Idle when the link goes standby (`processKeepalive`,
    /// `internalKeepalive`, `srtcore/group.cpp:4185-4233`), which lists a
    /// stranded member Pending again. Looked at again every
    /// [`MASKED_MEMBER_RECHECK`] until it reads Idle.
    Masked,
    /// Still connecting.
    Handshaking,
}

/// Classify one watched member from its socket's **live** state, read
/// first, and its row in the group listing read after (`None` when not
/// listed). `forced` reads it as stranded (the test hook,
/// `IoCommand::TestStrandMember`); `backup` is the group's mode.
///
/// Stranded is `live == CONNECTED` while listed Pending, or listed with
/// `sockstate` `CONNECTING`. libsrt's handshake writes the member Idle
/// with `laststatus` `CONNECTED` under the group lock and only then stores
/// the socket's `m_Status = SRTS_CONNECTED`, an atomic (vendored
/// `srtcore/core.cpp:5177-5196`); a live `CONNECTED` read before the
/// listing therefore guarantees the listing sees that write, unless
/// something wrote over it afterwards. After a member is added only
/// `groupConnect` writes Pending (`srtcore/api.cpp:1783`, `:1822`), and
/// nothing turns a Pending **send** state into anything but Broken: both
/// send paths use only an Idle or Running member and set a Pending one
/// aside, checking it for failure alone (`srtcore/group.cpp:1289-1335`
/// broadcast, `:2855-2890` and `:3296-3345` backup). So a caller member
/// read this way never sends. Its **receive** state is another matter: the
/// first data packet on the member takes it from Pending to Running
/// (`srtcore/core.cpp:11131-11136`), and the listing then shows the member
/// Running (`copyGroupData`, `srtcore/group.cpp:1982`) — the cases below.
///
/// **Sound only for members this bridge spawned into a caller group.** On a
/// listener's mirror group libsrt marks the socket connected *before* it
/// writes the member Idle (`srtcore/api.cpp:796` then `:865`), so Pending on
/// a connected socket is an ordinary instant there.
///
/// Running with `sockstate` `CONNECTED` in a broadcast group is left alone
/// ([`Verdict::Confirmed`]) even though it can hide a stranded send state:
/// data has arrived on it, so the member works for receiving, which is all a
/// caller group that receives needs, and libsrt exposes no per-direction
/// state to tell the two apart. A stranded sender's member receives no data
/// and stays listed Pending.
fn classify_watched(
    live: SocketStatus,
    row: Option<(MemberStatus, SocketStatus)>,
    forced: bool,
    backup: bool,
) -> Verdict {
    let Some((member, listed)) = row else {
        return Verdict::Gone;
    };
    if member == MemberStatus::Broken {
        return if live == SocketStatus::Connected { Verdict::BrokenLive } else { Verdict::Gone };
    }
    if live == SocketStatus::Connected
        && (forced || member == MemberStatus::Pending || listed == SocketStatus::Connecting)
    {
        return Verdict::Stranded;
    }
    if listed == SocketStatus::Connected {
        match member {
            MemberStatus::Idle => return Verdict::Confirmed,
            MemberStatus::Running if backup => return Verdict::Masked,
            MemberStatus::Running => return Verdict::Confirmed,
            _ => {}
        }
    }
    Verdict::Handshaking
}

/// What to do with a watched member after one look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Look again at the next check.
    Keep,
    /// Look again no earlier than this.
    Recheck(Instant),
    /// Stop watching it; close every member it superseded.
    Drop,
    /// Close it and every member it superseded; leave re-adding to the
    /// application.
    Abandon,
    /// Replace it ([`repair_plan`]).
    Repair,
}

/// The time half of a look: grace, connect deadline, and holding a member
/// until what it superseded has been closed. `w.supersedes` is already
/// closed and emptied when its linger ran out on this look.
fn next_step(w: &mut WatchedMember, verdict: Verdict, now: Instant) -> Step {
    match verdict {
        Verdict::Gone => Step::Drop,
        Verdict::Stranded | Verdict::BrokenLive => {
            let since = *w.stranded_since.get_or_insert(now);
            if now.saturating_duration_since(since) >= STRANDED_MEMBER_GRACE {
                Step::Repair
            } else {
                Step::Keep
            }
        }
        Verdict::Confirmed => {
            w.stranded_since = None;
            if w.supersedes.is_empty() { Step::Drop } else { Step::Keep }
        }
        Verdict::Masked => {
            w.stranded_since = None;
            if w.supersedes.is_empty() {
                Step::Recheck(now + MASKED_MEMBER_RECHECK)
            } else {
                Step::Keep
            }
        }
        Verdict::Handshaking => {
            w.stranded_since = None;
            if now < w.resolve_by {
                Step::Keep
            } else if is_terminal_status(w.live) {
                // libsrt failed it and should have said so by now.
                Step::Abandon
            } else {
                // Past its connect timeout and still neither up nor failed.
                Step::Repair
            }
        }
    }
}

/// How a member found stranded is replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepairPlan {
    /// Close it, and leave re-adding it to the application: it has been
    /// replaced [`MAX_STRANDED_REPAIRS`] times.
    CloseNow,
    /// Close it now; another member for the same endpoint replaces it. That
    /// sibling is up already (no longer watched), or it is still watched —
    /// re-added by the application meanwhile — and another member is up at
    /// the peer.
    JoinSibling(SocketId),
    /// A watched sibling replaces it, but nothing else is up at the peer:
    /// the sibling closes this one once it is up (its `supersedes`).
    HandToSibling(SocketId),
    /// Close it, then connect the same endpoint again: another member is up
    /// at the peer, so the peer's mirror group keeps a member.
    CloseThenSpawn,
    /// Connect the same endpoint again, and close this one only once that is
    /// up: nothing else is up at the peer, connecting, or listed Broken
    /// ([`weigh_others`]).
    SpawnThenClose,
    /// Nothing else is up at the peer, but another member is still in its
    /// handshake, or is listed Broken and about to be replaced itself
    /// ([`weigh_others`]): decide once that has resolved, at a later look.
    Wait,
}

/// `sibling`: another listed, [`in_flight`] member carrying the same token,
/// and whether the bridge is still watching it. `others_at_peer`: another
/// member is up at the peer. `others_resolving`: another member the bridge
/// spawned is still in its handshake, or is listed Broken on a connected
/// socket and replaced in turn. [`weigh_others`] reads both.
///
/// **The peer must never list more members than the bond has, nor none.**
///
/// None: closing a connected member sends its peer a shutdown, and a
/// listener's mirror group that loses its last member fails whole — the
/// listener drops the session, which is the redial this repair exists to
/// avoid (and an emptied caller group restarts its sequence numbers). So a
/// stranded member that is the only one up at the peer stays until its
/// replacement is up: make before break.
///
/// More: while the two overlap the peer lists both as live members of the
/// session, and a bilbycast-edge listener measures redundancy against the
/// most live members a session has had. Any other member up at the peer
/// during the overlap reads as one member more than the bond has, and once
/// the stranded member leaves, one is reported missing for good. So
/// whenever another member is up at the peer, the stranded member is closed
/// **first** — that costs nothing: a stranded member carries nothing, and
/// the peer only sees the ordinary short dip of a member re-added from a
/// new source port — and while another member is still connecting (a slow
/// path's handshake), which would come up in the middle of an overlap, the
/// repair waits until it has resolved: up, it makes closing first safe;
/// failed, make before break is. The wait is bounded by that member's own
/// connect deadline (its spawn plus its connect timeout plus
/// [`HANDSHAKE_TTL_SLACK`]). A member listed Broken on a connected socket
/// weighs as [`weigh_others`] says. The wait is not free: the stranded
/// member carries nothing and the connecting one nothing yet, so a
/// connecting member that never comes up holds the group's media off until
/// that deadline — a receiver's as much as a sender's, as group receive
/// skips a member listed `CONNECTING` (vendored `srtcore/group.cpp:2108-2112`)
/// — where make before break would have restored it within a second. It is
/// paid only while nothing is up at the peer and something is still
/// connecting — in practice a group's first connect with a slow or dark
/// link — and buys a peer that never miscounts the session for the rest of
/// its life.
fn repair_plan(
    repairs: u8,
    sibling: Option<(SocketId, bool)>,
    others_at_peer: bool,
    others_resolving: bool,
) -> RepairPlan {
    match sibling {
        Some((id, false)) => RepairPlan::JoinSibling(id),
        None if repairs >= MAX_STRANDED_REPAIRS => RepairPlan::CloseNow,
        Some((id, true)) if others_at_peer => RepairPlan::JoinSibling(id),
        None if others_at_peer => RepairPlan::CloseThenSpawn,
        _ if others_resolving => RepairPlan::Wait,
        Some((id, true)) => RepairPlan::HandToSibling(id),
        None => RepairPlan::SpawnThenClose,
    }
}

/// [`repair_plan`]'s `others_at_peer` and `others_resolving`, for a member
/// that is (`broken`) or is not itself listed Broken on a connected socket
/// ([`Verdict::BrokenLive`]), from what the rest of the group shows: `up`,
/// another member is [`at_peer`] ([`other_member_at_peer`]); `broken_live`,
/// another watched member is listed Broken on a connected socket
/// ([`other_member_broken_live`]); `handshaking`, another is still in its
/// handshake ([`other_member_handshaking`]).
///
/// A member listed Broken on a connected socket is at the peer as well, and
/// in a group that only receives it stays there until the bridge replaces
/// it (see [`at_peer`]). Left out, it let a stranded member overlap its
/// replacement beside it, and two such members overlap side by side: the
/// peer listed three members of a bond of two. So:
/// - For a member that is itself Broken it counts as up at the peer, and the
///   first of two such members to be replaced closes first: two Broken
///   members never wait on each other. (In a group that sends, libsrt closes
///   both at its next send whatever the bridge does, the one a make before
///   break would keep included.)
/// - For any other member it is a reason to wait. Its own repair counts a
///   stranded member as up at the peer and closes first, and the stranded
///   member then waits on that replacement's handshake like any other.
///   Counting it as up instead would close the stranded member first and
///   leave the group, on this side, only a Broken member and a handshake —
///   libsrt reads that `CONNECTING`, and `BROKEN` should the handshake fail
///   (`CUDTGroup::getStatus`, vendored `srtcore/group.cpp:964-1021`) —
///   where waiting keeps the stranded member, listed Pending on a connected
///   socket, reading the group `CONNECTED`. The wait ends: a watched member
///   listed Broken is replaced (and no longer watched), closed or gone a
///   [`STRANDED_MEMBER_GRACE`] after it was first found so, or, waiting
///   itself, once the handshake it waits on resolves. It never waits on this
///   member: a stranded member it counts as up, and one past its connect
///   deadline is no handshake to wait on.
fn weigh_others(broken: bool, up: bool, broken_live: bool, handshaking: bool) -> (bool, bool) {
    (up || (broken && broken_live), handshaking || (!broken && broken_live))
}

/// Whether a listed member is up at its peer as well as here, and stays
/// there while another is replaced: listed anything but Broken, on a socket
/// that is connected. A caller member's socket is connected only once the
/// peer has answered its handshake, so the peer has it too. That includes a
/// member libsrt stranded, which sends nothing here but which its peer lists
/// as a live member.
///
/// A member listed Broken on a connected socket is at the peer too, but
/// whether it stays depends on the group: libsrt closes a Broken member at
/// the group's next send (vendored `srtcore/group.cpp:1262-1300` and
/// `:3407-3439` broadcast, `:3443-3475` backup), while its receive path only
/// sets one aside (`:2093-2125`, `:2413-2432`), so in a group that only
/// receives it stays until the bridge replaces it. It is left out here, and
/// weighed in [`weigh_others`].
fn at_peer(member: MemberStatus, live: SocketStatus) -> bool {
    member != MemberStatus::Broken && live == SocketStatus::Connected
}

/// Whether a listed member, other than those in `exclude`, is [`at_peer`].
/// Its socket is read now, so a member closed earlier in the same check
/// reads as gone even though the listing still has it.
fn other_member_at_peer(rows: &[SRT_SOCKGROUPDATA], exclude: &[SocketId]) -> bool {
    rows.iter().filter(|r| !exclude.contains(&r.id)).any(|r| {
        at_peer(map_member_status(r.memberstate), raw_state_to_status(unsafe { srt_getsockstate(r.id) }))
    })
}

/// Whether a watched member, other than those in `exclude`, is listed Broken
/// on a socket that is connected ([`Verdict::BrokenLive`]), so that the
/// bridge replaces it in turn. Its socket is read now, like
/// [`other_member_at_peer`]'s. Only watched members: their resolution is
/// the bridge's own, which is what bounds a wait on them.
fn other_member_broken_live<'a>(
    members: impl IntoIterator<Item = &'a WatchedMember>,
    rows: &[SRT_SOCKGROUPDATA],
    exclude: &[SocketId],
) -> bool {
    members.into_iter().filter(|e| !exclude.contains(&e.id)).any(|e| {
        rows.iter().any(|r| r.id == e.id && map_member_status(r.memberstate) == MemberStatus::Broken)
            && unsafe { srt_getsockstate(e.id) } == SRTS_CONNECTED
    })
}

/// Whether a watched member, other than those in `exclude`, is still in its
/// handshake: its socket neither connected nor dead, and its connect
/// deadline not yet passed. A member spawned earlier in the same check
/// counts (its state is still `Init`); one past its deadline does not, so a
/// wait on it is bounded.
fn other_member_handshaking<'a>(
    members: impl IntoIterator<Item = &'a WatchedMember>,
    exclude: &[SocketId],
    now: Instant,
) -> bool {
    members.into_iter().any(|e| {
        !exclude.contains(&e.id)
            && e.live != SocketStatus::Connected
            && !is_terminal_status(e.live)
            && now < e.resolve_by
    })
}

/// The members a repair of `w` closes: `w` and every stranded member it
/// already supersedes.
fn repair_chain(w: &WatchedMember) -> Vec<SocketId> {
    let mut chain = w.supersedes.clone();
    chain.push(w.id);
    chain
}

/// The [`repair_plan`] for watched member `w`, which is still in `watched`;
/// `broken`: it is listed Broken on a connected socket
/// ([`Verdict::BrokenLive`]). `spawned` holds the replacements spawned
/// earlier in this check, which `rows` (read before it) does not list.
fn plan_repair(
    w: &WatchedMember,
    broken: bool,
    watched: &[WatchedMember],
    spawned: &[WatchedMember],
    rows: &[SRT_SOCKGROUPDATA],
    now: Instant,
) -> RepairPlan {
    let token = w.endpoint.token;
    let chain = repair_chain(w);
    let sibling = spawned
        .iter()
        .find(|e| e.endpoint.token == token)
        .map(|e| (e.id, true))
        .or_else(|| {
            member_in_flight(rows, token, &chain)
                .map(|id| (id, watched.iter().chain(spawned).any(|e| e.id == id)))
        });
    let (others_at_peer, others_resolving) = weigh_others(
        broken,
        other_member_at_peer(rows, &chain),
        other_member_broken_live(watched.iter().chain(spawned), rows, &chain),
        other_member_handshaking(watched.iter().chain(spawned), &chain, now),
    );
    repair_plan(w.repairs, sibling, others_at_peer, others_resolving)
}

/// Why a member [`next_step`] chose to replace is being replaced, for logs.
fn stranded_reason(verdict: Verdict, forced: bool) -> &'static str {
    match verdict {
        Verdict::BrokenLive => "is listed broken by libsrt on a connected socket",
        Verdict::Handshaking => "is still connecting after its connect timeout",
        _ if forced => "was marked stranded by the test hook",
        _ => "finished its handshake but libsrt left it pending",
    }
}

/// Close group members the bridge has given up on. Closing a member removes
/// it from its group at once (`CUDTUnited::close`, vendored
/// `srtcore/api.cpp:2229-2237`) and does not block: libsrt makes every
/// member non-blocking (`srtcore/api.cpp:1689`). An id libsrt has already
/// disposed of is a harmless miss.
fn close_members(ids: &[SocketId]) {
    for id in ids {
        unsafe { srt_close(*id) };
    }
}

/// Replace group members that libsrt stranded at connect: handshake
/// finished, socket connected, but listed `Pending` for good, so libsrt
/// never sends on them.
///
/// # The defect (libsrt v1.5.7, vendored)
///
/// `groupConnect` starts each member's handshake (`connectIn`), reads the
/// member's status, then writes the member `Pending` under the group lock
/// (`srtcore/api.cpp:1712`, `:1747-1751`, `:1822`). The handshake runs on
/// libsrt's receive thread, and on a loopback or LAN path, or a loaded
/// host, it can finish first: `postConnect` writes the member Idle
/// (`srtcore/core.cpp:5185-5188`), and `groupConnect`'s later write puts it
/// back to Pending. Nothing ever promotes Pending again, and libsrt never
/// sends on a Pending member (`srtcore/group.cpp:1323-1335`). Two shapes:
/// the listing shows Pending with `sockstate` `CONNECTED` (the handshake
/// finished before the status read), or Pending with `CONNECTING` while
/// the socket is in fact connected (it finished between the read and the
/// write) — group receive skips a `CONNECTING` member too
/// (`srtcore/group.cpp:2108-2132`), so that one carries nothing either way.
///
/// The cost was silent. In a group with another live member, the link
/// carried nothing while every listing called it "handshake in progress",
/// so bilbycast-edge's supervisor waited on it for ever: redundancy lost
/// with no event but a `srt_bond_member_down` that never resolved. As the
/// group's only connected member, `getStatus` read the group `CONNECTED`
/// through the member's socket, the first send failed with an ERR the
/// bridge rightly ignores, and every later send would-blocked: a bonded
/// output stalled for good with status Connected. It was the residual
/// intermittent failure of `tests/group_members.rs`.
///
/// # The repair
///
/// Every member this bridge spawns into a caller group (`ConnectGroup`,
/// `AddGroupMember`, and its own replacements) is watched until it is up.
/// Every [`STRANDED_CHECK`] each watched member's live socket state is read,
/// then the group listing, and [`classify_watched`] judges it. One read
/// stranded for [`STRANDED_MEMBER_GRACE`] is replaced by connecting the
/// same [`GroupEndpoint`] again. While another member is up at the peer
/// ([`at_peer`] — a stranded member counts, as its peer lists it live), the
/// stranded member is closed first. While none is, it stays until its
/// replacement is up and has been for [`superseded_linger`], and is closed
/// then, or as soon as the replacement fails — closing it first would empty
/// the peer's mirror group, which then fails whole: the redial this exists
/// to avoid. And while none is but another member is still in its
/// handshake, the repair waits for that to resolve, up to that member's
/// connect deadline, so that it cannot come up in the middle of an overlap.
/// [`repair_plan`] has why the peer must never see an overlap beside
/// another member. A member also reads stranded once its own connect
/// timeout plus [`HANDSHAKE_TTL_SLACK`] has passed with it still
/// unresolved, whatever the reason, and one listed Broken on a connected
/// socket (see [`connect_group`]) is replaced the same way. That one is at
/// the peer too, for as long as the group sends nothing: it counts as up
/// for another member listed Broken, and any other member waits for its
/// replacement ([`weigh_others`]).
///
/// The grace and that wait put a replacement no later than about a second
/// past a sibling's connect timeout, counted from when that sibling was
/// spawned: with the members themselves, or, behind a member listed Broken,
/// a grace later as its replacement. Inside bilbycast-edge's
/// `degrade_after` (its connect timeout + 2 s, at least 5 s), except when
/// such a late replacement never comes up: the edge then reports the member
/// down until its own replacement is up.
///
/// A replacement is watched like any member, at most
/// [`MAX_STRANDED_REPAIRS`] deep; past that the stranded member is closed
/// and re-adding it is left to the application. Everything runs on this
/// thread, as do member listings and `AddGroupMember`, so an application
/// listing always shows the endpoint as the stranded member or its pending
/// replacement, never absent, and an application that re-adds anyway is
/// absorbed by [`add_group_member`]'s one-handshake-per-token rule.
///
/// Only caller groups are watched: see [`classify_watched`] for why the
/// test is unsound on a listener's mirror group, which libsrt does not
/// strand anyway. Logged at warn; no event.
fn check_stranded_members(
    sockets: &mut HashMap<SocketId, SocketState>,
    rows: &mut Vec<SRT_SOCKGROUPDATA>,
    groups: &mut Vec<SocketId>,
) {
    groups.clear();
    groups.extend(
        sockets
            .iter()
            .filter(|(_, s)| {
                !s.watched.is_empty()
                    && s.last_status != SocketStatus::Init
                    && !is_terminal_status(s.last_status)
            })
            .map(|(id, _)| *id),
    );
    if groups.is_empty() {
        return;
    }
    let now = Instant::now();
    for grp in groups.iter().copied() {
        check_group(grp, sockets, rows, now);
    }
}

fn check_group(
    grp: SocketId,
    sockets: &mut HashMap<SocketId, SocketState>,
    rows: &mut Vec<SRT_SOCKGROUPDATA>,
    now: Instant,
) {
    let Some(state) = sockets.get_mut(&grp) else {
        return;
    };
    if !state.watched.iter().any(|w| w.not_before <= now) {
        return;
    }
    let backup = state.backup;
    let mut watched = std::mem::take(&mut state.watched);

    // Live state first, then the listing: see `classify_watched`.
    for w in watched.iter_mut() {
        w.live = raw_state_to_status(unsafe { srt_getsockstate(w.id) });
    }
    read_group_rows(grp, rows);

    let mut spawned: Vec<WatchedMember> = Vec::new();
    let mut idx = 0;
    while idx < watched.len() {
        if watched[idx].not_before > now {
            idx += 1;
            continue;
        }
        let row = rows
            .iter()
            .find(|r| r.id == watched[idx].id)
            .map(|r| (map_member_status(r.memberstate), raw_state_to_status(r.sockstate)));
        let w = &mut watched[idx];
        let verdict = classify_watched(w.live, row, w.forced, backup);

        if matches!(verdict, Verdict::Confirmed | Verdict::Masked) && !w.supersedes.is_empty() {
            let at = *w.close_superseded_at.get_or_insert_with(|| now + superseded_linger(w.id));
            if now >= at {
                tracing::debug!(
                    "srt-io: group {} member @{} (token {}) is up; closing the stranded {:?} it replaced",
                    grp,
                    w.id,
                    w.endpoint.token,
                    w.supersedes,
                );
                close_members(&w.supersedes);
                w.supersedes.clear();
            }
        }

        match next_step(w, verdict, now) {
            Step::Keep => idx += 1,
            Step::Recheck(at) => {
                w.not_before = at;
                idx += 1;
            }
            Step::Drop => {
                let w = watched.swap_remove(idx);
                if !w.supersedes.is_empty() {
                    tracing::warn!(
                        "srt-io: group {} member @{} (token {}, peer {}, source {:?}), which replaced \
                         the stranded {:?}, is gone; closed those too, leaving the member for the \
                         application to re-add",
                        grp,
                        w.id,
                        w.endpoint.token,
                        w.endpoint.addr,
                        w.endpoint.local_addr,
                        w.supersedes,
                    );
                    close_members(&w.supersedes);
                }
            }
            Step::Abandon => {
                let w = watched.swap_remove(idx);
                tracing::warn!(
                    "srt-io: group {} member @{} (token {}, peer {}, source {:?}) is still listed \
                     unresolved (member, socket: {:?}) past its connect timeout, though its socket \
                     is {:?}; closed it, leaving the member for the application to re-add",
                    grp,
                    w.id,
                    w.endpoint.token,
                    w.endpoint.addr,
                    w.endpoint.local_addr,
                    row,
                    w.live,
                );
                close_members(&[w.id]);
                close_members(&w.supersedes);
            }
            Step::Repair => match plan_repair(
                &watched[idx],
                verdict == Verdict::BrokenLive,
                &watched,
                &spawned,
                rows,
                now,
            ) {
                RepairPlan::Wait => {
                    let w = &mut watched[idx];
                    if !w.waiting {
                        w.waiting = true;
                        tracing::debug!(
                            "srt-io: group {} member @{} (token {}) {}; replacing it once another \
                             member's handshake, or the replacement of one listed broken, has \
                             resolved, so its peer never lists more members than the bond has",
                            grp,
                            w.id,
                            w.endpoint.token,
                            stranded_reason(verdict, w.forced),
                        );
                    }
                    idx += 1;
                }
                plan => {
                    let w = watched.swap_remove(idx);
                    repair_stranded(grp, w, verdict, plan, &mut watched, &mut spawned, now);
                }
            },
        }
    }
    watched.extend(spawned);

    let Some(state) = sockets.get_mut(&grp) else {
        return;
    };
    state.watched = watched;
    // The state poll can hold a fresh group at Connecting while its members
    // handshake, and in a loop with nothing else connected its next look is
    // about 10 s away; take the group back to Connected as soon as libsrt
    // says so.
    if state.last_status == SocketStatus::Connecting
        && unsafe { srt_getsockstate(grp) } == SRTS_CONNECTED
    {
        update_status(state, SocketStatus::Connected);
    }
}

/// Carry out `plan` ([`plan_repair`], never [`RepairPlan::Wait`]) for a
/// watched member [`next_step`] chose to replace. `watched` holds the
/// group's other watched members; a new replacement goes to `spawned`.
fn repair_stranded(
    grp: SocketId,
    w: WatchedMember,
    verdict: Verdict,
    plan: RepairPlan,
    watched: &mut [WatchedMember],
    spawned: &mut Vec<WatchedMember>,
    now: Instant,
) {
    if !w.forced {
        STRANDED_REPAIRS.fetch_add(1, Ordering::Relaxed);
    }
    let what = stranded_reason(verdict, w.forced);
    let token = w.endpoint.token;
    let chain = repair_chain(&w);
    match plan {
        RepairPlan::JoinSibling(other) | RepairPlan::HandToSibling(other) => {
            tracing::warn!(
                "srt-io: group {} member @{} (token {}, peer {}, source {:?}) {}, so it would never \
                 carry a packet; @{} already carries or re-connects that endpoint and replaces it",
                grp,
                w.id,
                token,
                w.endpoint.addr,
                w.endpoint.local_addr,
                what,
                other,
            );
            // Closed now while another member is up at the peer, else
            // handed to the sibling to close once it is up: see
            // `repair_plan`.
            let hand_to = (plan == RepairPlan::HandToSibling(other))
                .then(|| watched.iter_mut().chain(spawned.iter_mut()).find(|e| e.id == other))
                .flatten();
            match hand_to {
                Some(e) => e.supersedes.extend(chain),
                None => close_members(&chain),
            }
        }
        RepairPlan::CloseNow => {
            tracing::warn!(
                "srt-io: group {} member @{} (token {}, peer {}, source {:?}) {}, so it would never \
                 carry a packet; closed it (repair limit {} reached; left for the application to \
                 re-add)",
                grp,
                w.id,
                token,
                w.endpoint.addr,
                w.endpoint.local_addr,
                what,
                MAX_STRANDED_REPAIRS,
            );
            close_members(&chain);
        }
        RepairPlan::CloseThenSpawn | RepairPlan::SpawnThenClose => {
            let close_first = plan == RepairPlan::CloseThenSpawn;
            if close_first {
                close_members(&chain);
            }
            match connect_group(grp, std::slice::from_ref(&w.endpoint)).single() {
                Ok(new) => {
                    let order = if close_first {
                        format!("closed it and re-connected the same endpoint as @{new}")
                    } else {
                        format!(
                            "re-connected the same endpoint as @{new}, and will close @{} once that \
                             is up, as nothing else is up at the peer",
                            w.id
                        )
                    };
                    tracing::warn!(
                        "srt-io: group {} member @{} (token {}, peer {}, source {:?}) {}, so it would \
                         never carry a packet; {} (repair {}/{})",
                        grp,
                        w.id,
                        token,
                        w.endpoint.addr,
                        w.endpoint.local_addr,
                        what,
                        order,
                        w.repairs + 1,
                        MAX_STRANDED_REPAIRS,
                    );
                    let mut next = WatchedMember::spawned(new, w.endpoint, now);
                    next.repairs = w.repairs + 1;
                    if !close_first {
                        next.supersedes = chain;
                    }
                    spawned.push(next);
                }
                Err(err) => {
                    tracing::warn!(
                        "srt-io: group {} member @{} (token {}, peer {}, source {:?}) {}, so it would \
                         never carry a packet; re-connecting the same endpoint failed ({:?}), so closed \
                         it, leaving the member for the application to re-add",
                        grp,
                        w.id,
                        token,
                        w.endpoint.addr,
                        w.endpoint.local_addr,
                        what,
                        err,
                    );
                    if !close_first {
                        close_members(&chain);
                    }
                }
            }
        }
        RepairPlan::Wait => unreachable!("check_group keeps a member that waits"),
    }
}

/// [`IoCommand::TestStrandMember`]: mark the healthy member carrying
/// `endpoint.token` stranded.
#[cfg(feature = "test-hooks")]
fn force_stranded(
    id: SocketId,
    endpoint: GroupEndpoint,
    sockets: &mut HashMap<SocketId, SocketState>,
) -> Result<(), SrtError> {
    let Some(state) = sockets
        .get_mut(&id)
        .filter(|s| s.is_group && !is_terminal_status(s.last_status))
    else {
        return Err(SrtError::ConnectionLost);
    };
    let mut rows = Vec::new();
    read_group_rows(id, &mut rows);
    let superseded: Vec<SocketId> =
        state.watched.iter().flat_map(|w| w.supersedes.iter().copied()).collect();
    let member = rows
        .iter()
        .find(|r| {
            r.token == endpoint.token
                && !superseded.contains(&r.id)
                && matches!(
                    map_member_status(r.memberstate),
                    MemberStatus::Idle | MemberStatus::Running
                )
                && unsafe { srt_getsockstate(r.id) } == SRTS_CONNECTED
        })
        .map(|r| r.id)
        .ok_or(SrtError::InvalidParam)?;
    let now = Instant::now();
    match state.watched.iter_mut().find(|w| w.id == member) {
        Some(w) => {
            w.forced = true;
            w.not_before = now;
        }
        None => {
            let mut w = WatchedMember::spawned(member, endpoint, now);
            w.forced = true;
            state.watched.push(w);
        }
    }
    Ok(())
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
                token: m.token,
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
    unsafe {
        srt_epoll_add_usock(epoll_id, sock, &events);
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
        // actually live. A freshly created group reports SRTS_BROKEN until
        // `ConnectGroup` has run and given it members (`CUDTGroup::getStatus`
        // on a memberless group); `RegisterSocket` no longer applies that to
        // a group, and this guard keeps any other pre-connect terminal
        // reading from tearing the send channel off before it ever connected.
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

    /// A group is registered before `ConnectGroup` gives it members, and
    /// libsrt reads a memberless group as `SRTS_BROKEN`. Applying that at
    /// registration dropped the receive channel, so a bonded caller's `recv`
    /// failed before it ever connected.
    #[test]
    fn registering_a_fresh_group_keeps_its_channels() {
        libsrt_sys::ensure_initialized();
        let epoll_id = unsafe { srt_epoll_create() };
        assert!(epoll_id >= 0, "srt_epoll_create failed");
        let mut sockets: HashMap<SocketId, SocketState> = HashMap::new();

        let (tx, mut rx) = oneshot::channel();
        process_command(
            IoCommand::CreateGroup {
                mode: SRT_GTYPE_BROADCAST,
                config: {
                    let mut c = SrtConfig::default();
                    c.live_defaults();
                    c
                },
                reply: tx,
            },
            epoll_id,
            &mut sockets,
        );
        let grp = rx.try_recv().expect("no reply").expect("srt_create_group failed");
        // The premise: libsrt does call the memberless group broken.
        assert!(is_terminal_status(raw_state_to_status(unsafe { srt_getsockstate(grp) })));
        assert!(group_err_is_real(grp));

        let (recv_tx, _recv_rx) = mpsc::unbounded_channel();
        let (_send_tx, send_rx) = mpsc::channel(1);
        let (status_tx, _status_rx) = watch::channel(SocketStatus::Init);
        process_command(
            IoCommand::RegisterSocket { id: grp, recv_tx, send_rx, status_tx },
            epoll_id,
            &mut sockets,
        );
        let state = &sockets[&grp];
        assert!(state.recv_tx.is_some(), "registration dropped the group's receive channel");
        assert!(state.send_rx.is_some(), "registration dropped the group's send channel");
        assert_eq!(state.last_status, SocketStatus::Init);

        close_and_release(epoll_id, grp, &mut sockets);
        unsafe { srt_epoll_release(epoll_id) };
    }

    // ── Group members (bonding) ─────────────────────────────────────────

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn storage_to_addr<T>(raw: &T) -> Option<SocketAddr> {
        let st: libc::sockaddr_storage = unsafe { std::mem::transmute_copy(raw) };
        sockaddr_storage_to_socket_addr(&st)
    }

    /// The member record handed to `srt_connect_group` carries the source,
    /// weight and token of its endpoint. Before this, every member was
    /// prepared with a null source and libsrt's default weight 0 / token -1,
    /// so a configured source address and weight never reached libsrt
    /// (bilbycast-edge #184).
    #[test]
    fn prepare_target_carries_source_weight_and_token() {
        let ep = GroupEndpoint {
            addr: sa("10.1.2.3:9000"),
            local_addr: Some(sa("192.0.2.7:4100")),
            weight: 7,
            token: 3,
        };
        let t = prepare_target(&ep);
        assert_eq!(storage_to_addr(&t.peeraddr), Some(ep.addr));
        assert_eq!(storage_to_addr(&t.srcaddr), ep.local_addr);
        assert_eq!(t.weight, 7);
        assert_eq!(t.token, 3);
        assert_eq!(t.errorcode, 0);
    }

    /// No source: libsrt zeroes it and gives it the target's family, which
    /// `groupConnect` reads as "do not bind". A source of the wrong family
    /// would make libsrt refuse the whole group call.
    #[test]
    fn prepare_target_without_source_leaves_it_empty_with_target_family() {
        let t = prepare_target(&GroupEndpoint::new(sa("[2001:db8::5]:9000"), 0));
        assert_eq!(t.srcaddr.ss_family as i32, libc::AF_INET6);
        assert_eq!(storage_to_addr(&t.srcaddr), Some(sa("[::]:0")));
        assert_eq!(t.weight, 0);
        assert_eq!(t.token, 0);
    }

    /// A group the bridge does not track (closed, or never created) is never
    /// revived by a re-add.
    #[test]
    fn add_member_to_an_untracked_group_is_refused() {
        let mut sockets: HashMap<SocketId, SocketState> = HashMap::new();
        let ep = GroupEndpoint::new(sa("127.0.0.1:9"), 0);
        assert_eq!(
            add_group_member(0x4000_0001, &ep, &mut sockets),
            Err(SrtError::ConnectionLost)
        );
    }

    /// The atomic half of the "only while a member is live" rule: even when
    /// the bridge still believes the group is connected, the add is refused
    /// unless libsrt itself reports an Idle or Running member — and nothing
    /// is spawned. A member added to a group with no live link counts as
    /// healthy in libsrt's own failure test, so the group would sit in
    /// `Connecting` (sends stalled) instead of breaking and being redialled.
    #[test]
    fn add_member_is_refused_while_no_member_is_idle_or_running() {
        libsrt_sys::ensure_initialized();
        let epoll_id = unsafe { srt_epoll_create() };
        assert!(epoll_id >= 0, "srt_epoll_create failed");
        let mut sockets: HashMap<SocketId, SocketState> = HashMap::new();

        let (tx, mut rx) = oneshot::channel();
        process_command(
            IoCommand::CreateGroup {
                mode: SRT_GTYPE_BROADCAST,
                config: {
                    let mut c = SrtConfig::default();
                    c.live_defaults();
                    c
                },
                reply: tx,
            },
            epoll_id,
            &mut sockets,
        );
        let grp = rx.try_recv().expect("no reply").expect("srt_create_group failed");
        // Pretend the bridge still has the group as live: the libsrt check
        // must stand on its own.
        sockets.get_mut(&grp).unwrap().last_status = SocketStatus::Connected;
        assert_ne!(unsafe { srt_getsockstate(grp) }, SRTS_CONNECTED);

        let (tx, mut rx) = oneshot::channel();
        process_command(
            IoCommand::AddGroupMember {
                id: grp,
                endpoint: GroupEndpoint::new(sa("127.0.0.1:9"), 0),
                reply: tx,
            },
            epoll_id,
            &mut sockets,
        );
        assert_eq!(rx.try_recv().expect("no reply"), Err(SrtError::ConnectionLost));
        assert!(
            get_group_member_stats(grp).is_empty(),
            "a refused add still spawned a member"
        );

        close_and_release(epoll_id, grp, &mut sockets);
        unsafe { srt_epoll_release(epoll_id) };
    }

    /// A group joins the bridge's epoll only when `ConnectGroup` succeeds.
    /// `SrtGroupBuilder::connect` closes the group whose connect spawned no
    /// member, still at `Init`; asking libsrt to unsubscribe it from an
    /// epoll it never joined makes libsrt log an internal error at Error
    /// level ("IPE: update struck E… which is NOT SUBSCRIBED to @…"), once
    /// per failed attempt of a caller retrying an unbindable source.
    #[test]
    fn closing_a_group_that_never_connected_logs_no_internal_error() {
        use std::ffi::{CStr, c_void};
        use std::sync::Mutex;

        static NOT_SUBSCRIBED: Mutex<Vec<String>> = Mutex::new(Vec::new());
        unsafe extern "C" fn capture(
            _opaque: *mut c_void,
            _level: c_int,
            _file: *const c_char,
            _line: c_int,
            _area: *const c_char,
            message: *const c_char,
        ) {
            if message.is_null() {
                return;
            }
            let line = unsafe { CStr::from_ptr(message) }.to_string_lossy().into_owned();
            if line.contains("NOT SUBSCRIBED") {
                if let Ok(mut lines) = NOT_SUBSCRIBED.lock() {
                    lines.push(line);
                }
            }
        }

        libsrt_sys::ensure_initialized();
        let epoll_id = unsafe { srt_epoll_create() };
        assert!(epoll_id >= 0, "srt_epoll_create failed");
        let mut sockets: HashMap<SocketId, SocketState> = HashMap::new();

        let (tx, mut rx) = oneshot::channel();
        process_command(
            IoCommand::CreateGroup {
                mode: SRT_GTYPE_BROADCAST,
                config: {
                    let mut c = SrtConfig::default();
                    c.live_defaults();
                    c
                },
                reply: tx,
            },
            epoll_id,
            &mut sockets,
        );
        let grp = rx.try_recv().expect("no reply").expect("srt_create_group failed");
        let (recv_tx, _recv_rx) = mpsc::unbounded_channel();
        let (_send_tx, send_rx) = mpsc::channel(1);
        let (status_tx, _status_rx) = watch::channel(SocketStatus::Init);
        process_command(
            IoCommand::RegisterSocket { id: grp, recv_tx, send_rx, status_tx },
            epoll_id,
            &mut sockets,
        );
        assert_eq!(sockets[&grp].last_status, SocketStatus::Init);

        // libsrt logs on the closing thread, so the line, if any, is in by
        // the time the close returns. Other tests' lines are told apart by
        // the group id.
        unsafe { srt_setloghandler(std::ptr::null_mut(), Some(capture)) };
        process_command(IoCommand::Close { id: grp }, epoll_id, &mut sockets);
        unsafe { srt_setloghandler(std::ptr::null_mut(), None) };

        assert!(!sockets.contains_key(&grp), "the group's bridge entry was kept");
        let ours = format!("@{grp}");
        let hits: Vec<String> = NOT_SUBSCRIBED
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains(&ours))
            .cloned()
            .collect();
        assert!(hits.is_empty(), "closing a never-connected group logged: {hits:?}");
        unsafe { srt_epoll_release(epoll_id) };
    }

    // ── Stranded members ───────────────────────────────────────────────

    use MemberStatus as M;
    use SocketStatus as S;

    fn watched(now: Instant) -> WatchedMember {
        WatchedMember::new(
            0x1234,
            GroupEndpoint::new(sa("127.0.0.1:9000"), 1),
            now + Duration::from_secs(4),
            now,
        )
    }

    /// The predicate, both libsrt overwrite shapes, and what is deliberately
    /// left alone. `live` is the socket's own state, `row` the listing.
    #[test]
    fn classify_watched_matrix() {
        /// live, listed (member, sockstate), forced, backup, verdict, why.
        type Case = (S, Option<(M, S)>, bool, bool, Verdict, &'static str);
        let cases: &[Case] = &[
            (S::Connected, Some((M::Pending, S::Connected)), false, false, Verdict::Stranded,
             "handshake done before groupConnect read the status"),
            (S::Connected, Some((M::Pending, S::Connecting)), false, false, Verdict::Stranded,
             "handshake done between the read and the write"),
            (S::Connected, Some((M::Running, S::Connecting)), false, false, Verdict::Stranded,
             "the second shape with data received: group recv still skips it"),
            (S::Connected, Some((M::Running, S::Connected)), false, false, Verdict::Confirmed,
             "broadcast Running: receiving works, send state unknowable — left alone"),
            (S::Connected, Some((M::Running, S::Connected)), false, true, Verdict::Masked,
             "backup Running: a keepalive can list it Pending again"),
            (S::Connected, Some((M::Idle, S::Connected)), false, false, Verdict::Confirmed,
             "Idle proves the send state is Idle"),
            (S::Connected, Some((M::Idle, S::Connected)), false, true, Verdict::Confirmed,
             "Idle in backup too"),
            (S::Connecting, Some((M::Pending, S::Connecting)), false, false, Verdict::Handshaking,
             "an ordinary handshake"),
            (S::Opened, Some((M::Pending, S::Connecting)), false, false, Verdict::Handshaking,
             "not even started"),
            (S::Broken, Some((M::Pending, S::Connecting)), false, false, Verdict::Handshaking,
             "failing: libsrt is about to list it Broken"),
            (S::Connected, Some((M::Broken, S::Broken)), false, false, Verdict::BrokenLive,
             "listed Broken on a connected socket"),
            (S::Broken, Some((M::Broken, S::Broken)), false, false, Verdict::Gone,
             "an ordinary failure"),
            (S::NonExist, Some((M::Broken, S::Connected)), false, false, Verdict::Gone,
             "an ordinary loss of a used link"),
            (S::Connected, None, false, false, Verdict::Gone, "no longer listed"),
            (S::NonExist, None, false, false, Verdict::Gone, "closed"),
            (S::Connected, Some((M::Idle, S::Connected)), true, false, Verdict::Stranded,
             "forced by the test hook"),
            (S::Connected, Some((M::Running, S::Connected)), true, true, Verdict::Stranded,
             "forced, backup"),
            (S::Broken, Some((M::Idle, S::Connected)), true, false, Verdict::Confirmed,
             "forced but no longer connected: nothing to replace"),
        ];
        for (live, row, forced, backup, want, why) in cases {
            assert_eq!(
                classify_watched(*live, *row, *forced, *backup),
                *want,
                "live {live:?}, row {row:?}, forced {forced}, backup {backup}: {why}"
            );
        }
    }

    /// One stranded reading is not acted on until it has persisted for the
    /// grace period; any other reading restarts the clock.
    #[test]
    fn a_stranded_member_is_repaired_only_after_the_grace() {
        let t0 = Instant::now();
        let mut w = watched(t0);
        w.live = S::Connected;
        assert_eq!(next_step(&mut w, Verdict::Stranded, t0), Step::Keep);
        assert_eq!(next_step(&mut w, Verdict::Stranded, t0 + Duration::from_millis(499)), Step::Keep);
        assert_eq!(next_step(&mut w, Verdict::Stranded, t0 + STRANDED_MEMBER_GRACE), Step::Repair);

        let mut w = watched(t0);
        assert_eq!(next_step(&mut w, Verdict::Stranded, t0), Step::Keep);
        assert_eq!(
            next_step(&mut w, Verdict::Handshaking, t0 + Duration::from_millis(200)),
            Step::Keep
        );
        assert_eq!(next_step(&mut w, Verdict::Stranded, t0 + Duration::from_millis(300)), Step::Keep);
        assert_eq!(next_step(&mut w, Verdict::Stranded, t0 + Duration::from_millis(799)), Step::Keep);
        assert_eq!(next_step(&mut w, Verdict::Stranded, t0 + Duration::from_millis(800)), Step::Repair);

        let mut w = watched(t0);
        assert_eq!(next_step(&mut w, Verdict::BrokenLive, t0), Step::Keep);
        assert_eq!(next_step(&mut w, Verdict::BrokenLive, t0 + STRANDED_MEMBER_GRACE), Step::Repair);
    }

    /// A member still unresolved past its connect deadline is not waited on
    /// for ever: replaced if its socket is alive, closed if it is dead.
    #[test]
    fn a_member_unresolved_past_its_connect_timeout_is_not_waited_on() {
        let t0 = Instant::now();
        let mut w = watched(t0);
        let deadline = w.resolve_by;
        w.live = S::Connecting;
        assert_eq!(
            next_step(&mut w, Verdict::Handshaking, deadline - Duration::from_millis(1)),
            Step::Keep
        );
        assert_eq!(next_step(&mut w, Verdict::Handshaking, deadline), Step::Repair);
        w.live = S::Broken;
        assert_eq!(next_step(&mut w, Verdict::Handshaking, deadline), Step::Abandon);
    }

    /// A member that is up stops being watched only once what it superseded
    /// has been closed; a backup member hiding its send state is looked at
    /// again, slowly, until it reads Idle.
    #[test]
    fn up_members_hold_until_their_predecessors_are_closed() {
        let t0 = Instant::now();
        let mut w = watched(t0);
        assert_eq!(next_step(&mut w, Verdict::Confirmed, t0), Step::Drop);
        assert_eq!(next_step(&mut w, Verdict::Masked, t0), Step::Recheck(t0 + MASKED_MEMBER_RECHECK));
        assert_eq!(next_step(&mut w, Verdict::Gone, t0), Step::Drop);

        w.supersedes.push(0x99);
        assert_eq!(next_step(&mut w, Verdict::Confirmed, t0), Step::Keep);
        assert_eq!(next_step(&mut w, Verdict::Masked, t0), Step::Keep);
        // Gone with predecessors: they are closed with it (by the caller).
        assert_eq!(next_step(&mut w, Verdict::Gone, t0), Step::Drop);
    }

    /// One handshake per endpoint, and a bounded chain of replacements.
    #[test]
    fn repair_plan_joins_a_sibling_and_stops_at_the_cap() {
        for (at_peer, handshaking) in [(false, false), (false, true), (true, false), (true, true)] {
            let plan = |repairs, sibling| repair_plan(repairs, sibling, at_peer, handshaking);
            // Up already, so no longer watched: it carries the endpoint.
            assert_eq!(plan(0, Some((7, false))), RepairPlan::JoinSibling(7));
            assert_eq!(plan(MAX_STRANDED_REPAIRS, Some((7, false))), RepairPlan::JoinSibling(7));
            // The cap stops a chain of replacements, never a sibling.
            assert_eq!(plan(MAX_STRANDED_REPAIRS, None), RepairPlan::CloseNow);
            assert_ne!(plan(MAX_STRANDED_REPAIRS, Some((7, true))), RepairPlan::CloseNow);
        }
    }

    /// The peer must never list more members than the bond has, nor none:
    /// close first whenever another member is up at the peer; make before
    /// break only when none is and none is connecting; otherwise wait for
    /// the connecting one to resolve.
    #[test]
    fn repair_plan_overlaps_only_when_nothing_else_is_up_or_connecting() {
        for repairs in [0, MAX_STRANDED_REPAIRS - 1] {
            for handshaking in [false, true] {
                assert_eq!(repair_plan(repairs, None, true, handshaking), RepairPlan::CloseThenSpawn);
                assert_eq!(
                    repair_plan(repairs, Some((7, true)), true, handshaking),
                    RepairPlan::JoinSibling(7)
                );
            }
            assert_eq!(repair_plan(repairs, None, false, true), RepairPlan::Wait);
            assert_eq!(repair_plan(repairs, Some((7, true)), false, true), RepairPlan::Wait);
            assert_eq!(repair_plan(repairs, None, false, false), RepairPlan::SpawnThenClose);
            assert_eq!(
                repair_plan(repairs, Some((7, true)), false, false),
                RepairPlan::HandToSibling(7)
            );
        }
    }

    /// Up at the peer: anything but Broken on a connected socket — a
    /// stranded member included, as its peer lists it live.
    #[test]
    fn at_peer_is_any_unbroken_member_on_a_connected_socket() {
        for m in [M::Pending, M::Idle, M::Running] {
            assert!(at_peer(m, S::Connected), "{m:?}");
            for live in [S::Init, S::Opened, S::Connecting, S::Broken, S::Closed, S::NonExist] {
                assert!(!at_peer(m, live), "{m:?} on {live:?}");
            }
        }
        assert!(!at_peer(M::Broken, S::Connected), "weighed in weigh_others, not here");
    }

    /// A member listed Broken on a connected socket is at the peer of a
    /// group that only receives, for as long as the bridge leaves it there.
    /// Two such members, or one beside a stranded member, must not overlap
    /// their replacements: the peer would list three members of a bond of
    /// two. Each case below is two members, A and B, replaced one after the
    /// other in one check; `plan(broken, up, broken_live, handshaking)` is
    /// what a member's repair decides.
    #[test]
    fn a_member_listed_broken_is_counted_at_the_peer_or_waited_on() {
        let plan = |broken, up, broken_live, handshaking| {
            let (at_peer, resolving) = weigh_others(broken, up, broken_live, handshaking);
            repair_plan(0, None, at_peer, resolving)
        };

        // Both listed Broken: A closes first, counting B up at the peer;
        // B then waits on A's replacement, and closes first once it is up.
        assert_eq!(plan(true, false, true, false), RepairPlan::CloseThenSpawn);
        assert_eq!(plan(true, false, false, true), RepairPlan::Wait);
        assert_eq!(plan(true, true, false, false), RepairPlan::CloseThenSpawn);

        // A stranded, B listed Broken, in either order. A waits while B
        // stands; B counts A up at the peer and closes first; A then waits
        // on B's replacement, and closes first once it is up.
        assert_eq!(plan(false, false, true, false), RepairPlan::Wait);
        assert_eq!(plan(true, true, false, false), RepairPlan::CloseThenSpawn);
        assert_eq!(plan(false, false, false, true), RepairPlan::Wait);
        assert_eq!(plan(false, true, false, false), RepairPlan::CloseThenSpawn);

        // Whatever else is listed, a Broken member counts another one up at
        // the peer and never waits on it; any other member waits on it.
        for up in [false, true] {
            for handshaking in [false, true] {
                assert_eq!(weigh_others(true, up, true, handshaking), (true, handshaking));
                assert_eq!(weigh_others(false, up, true, handshaking), (up, true));
            }
        }
        // With no member listed Broken, nothing changes.
        for broken in [false, true] {
            for up in [false, true] {
                for handshaking in [false, true] {
                    assert_eq!(weigh_others(broken, up, false, handshaking), (up, handshaking));
                }
            }
        }
        // Alone, either one makes before it breaks.
        assert_eq!(plan(true, false, false, false), RepairPlan::SpawnThenClose);
        assert_eq!(plan(false, false, false, false), RepairPlan::SpawnThenClose);
    }

    /// A handshake is waited on only while its socket is neither connected
    /// nor dead, and only until its connect deadline; the member being
    /// repaired, and what it supersedes, never count.
    #[test]
    fn only_a_live_handshake_inside_its_deadline_is_waited_on() {
        let t0 = Instant::now();
        let at = |live| {
            let mut w = watched(t0);
            w.live = live;
            w
        };
        let before = t0 + Duration::from_secs(1);
        // Spawned earlier in the same check: `Init` until the next.
        for live in [S::Init, S::Opened, S::Connecting] {
            assert!(other_member_handshaking([&at(live)], &[], before), "{live:?}");
        }
        for live in [S::Connected, S::Broken, S::Closing, S::Closed, S::NonExist] {
            assert!(!other_member_handshaking([&at(live)], &[], before), "{live:?}");
        }
        let connecting = at(S::Connecting);
        assert!(!other_member_handshaking([&connecting], &[], connecting.resolve_by), "past its deadline");
        assert!(!other_member_handshaking([&connecting], &[connecting.id], before), "excluded");
        assert!(!other_member_handshaking(std::iter::empty::<&WatchedMember>(), &[], before));
    }

    /// What `add_group_member` treats as an endpoint already being carried.
    #[test]
    fn in_flight_is_pending_or_live_on_a_socket_that_is_not_dead() {
        for m in [M::Pending, M::Idle, M::Running] {
            assert!(in_flight(m, S::Connected), "{m:?}");
            assert!(in_flight(m, S::Connecting), "{m:?}");
            assert!(!in_flight(m, S::Broken), "{m:?} on a broken socket");
            assert!(!in_flight(m, S::NonExist), "{m:?} on a closed socket");
        }
        assert!(!in_flight(M::Broken, S::Connected));
    }

    /// Only caller groups are watched: the predicate is unsound on a
    /// listener's mirror group (libsrt marks the socket connected before it
    /// writes the member Idle there), and nothing is watched before a group
    /// has members.
    #[test]
    fn only_members_the_bridge_spawns_are_watched() {
        libsrt_sys::ensure_initialized();
        let epoll_id = unsafe { srt_epoll_create() };
        assert!(epoll_id >= 0, "srt_epoll_create failed");
        let mut sockets: HashMap<SocketId, SocketState> = HashMap::new();

        let (tx, mut rx) = oneshot::channel();
        process_command(
            IoCommand::CreateGroup {
                mode: SRT_GTYPE_BACKUP,
                config: {
                    let mut c = SrtConfig::default();
                    c.live_defaults();
                    c
                },
                reply: tx,
            },
            epoll_id,
            &mut sockets,
        );
        let grp = rx.try_recv().expect("no reply").expect("srt_create_group failed");
        assert!(sockets[&grp].watched.is_empty());
        assert!(sockets[&grp].backup, "a backup group must read as one");

        let mut rows = Vec::new();
        read_group_rows(grp, &mut rows);
        assert!(rows.is_empty(), "a memberless group listed {} members", rows.len());

        // An accepted socket (or a listener's mirror group) is registered
        // this way: never watched.
        let sock = unsafe { srt_create_socket() };
        assert!(sock >= 0, "srt_create_socket failed");
        let (recv_tx, _recv_rx) = mpsc::unbounded_channel();
        let (_send_tx, send_rx) = mpsc::channel(1);
        let (status_tx, _status_rx) = watch::channel(SocketStatus::Init);
        process_command(
            IoCommand::RegisterSocket { id: sock, recv_tx, send_rx, status_tx },
            epoll_id,
            &mut sockets,
        );
        assert!(sockets[&sock].watched.is_empty());
        assert!(!sockets[&sock].backup);

        // Nothing to mark on a group without members.
        assert_eq!(
            force_stranded(grp, GroupEndpoint::new(sa("127.0.0.1:9"), 0), &mut sockets),
            Err(SrtError::InvalidParam)
        );
        assert!(sockets[&grp].watched.is_empty());

        // Never subscribed to the epoll (only connects and accepts are), so
        // close it directly: unsubscribing it makes libsrt log an internal
        // error.
        sockets.remove(&sock);
        unsafe { srt_close(sock) };
        close_and_release(epoll_id, grp, &mut sockets);
        unsafe { srt_epoll_release(epoll_id) };
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
