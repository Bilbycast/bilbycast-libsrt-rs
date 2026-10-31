# CLAUDE.md — bilbycast-libsrt-rs

## What Is This

Rust wrapper around Haivision's libsrt v1.5.7 for the bilbycast ecosystem. Provides async Tokio-compatible SRT sockets whose API is a **superset** of the bilbycast-srt pure-Rust implementation: the socket / listener / stats surface mirrors it deliberately, and native SRT bonding (`SrtGroup`, `SrtGroupBuilder`, `GroupMode`, `GroupMemberStats`, `MemberStatus`) exists only here. bilbycast-edge uses that bonding surface unconditionally, so this crate is its only SRT backend.

## Projects

| Crate | Role |
|-------|------|
| **libsrt-sys** | Raw FFI bindings to libsrt via bindgen. Vendored build from `vendor/srt/` (git submodule). |
| **srt-protocol** | Pure-Rust data types (config, stats, errors, access control). No libsrt dependency. API-compatible with bilbycast-srt/srt-protocol. |
| **srt-transport** | Async transport layer wrapping libsrt. SrtSocket, SrtListener, SrtGroup (bonding). Dedicated I/O thread with srt_epoll_wait bridged to Tokio via channels. |

## Build & Test

```bash
# Build all crates (requires OpenSSL and CMake for vendored libsrt build)
cargo build

# Run tests
cargo test

# Use system libsrt instead of vendored
cargo build --features libsrt-sys/system-libsrt

# Point to custom libsrt install
LIBSRT_DIR=/path/to/libsrt cargo build
```

### Prerequisites

- **CMake** (for vendored libsrt build)
- **OpenSSL** development headers (`libssl-dev` on Linux, `brew install openssl` on macOS)
- **Clang/LLVM** (for bindgen)
- **macOS**: `brew install cmake openssl`
- **Linux**: `apt install cmake libssl-dev clang`

## Architecture

### I/O Thread Design

All libsrt C API calls happen on a single dedicated OS thread (`srt-io`). Tokio tasks communicate with it via lock-free channels:

```
[Tokio tasks] <--mpsc/oneshot--> [I/O Thread (srt_epoll_uwait)] <--C API--> [libsrt]
```

- **Non-blocking**: All sockets use `SRTO_RCVSYN=false`, `SRTO_SNDSYN=false`
- **No Mutex on hot path**: Data flows through `mpsc::UnboundedSender` (recv) and command channels (send)
- **Thread safety**: libsrt sockets aren't thread-safe; single thread eliminates races
- **Global singleton**: One I/O thread per process via `OnceLock`

### Bonding

Native SRT bonding via libsrt's socket group API:
- `GroupMode::Broadcast` — SMPTE 2022-7 (all links active, deduplication by libsrt)
- `GroupMode::Backup` — primary/backup with failover

Each member is a `GroupEndpoint { addr, local_addr, weight, token }`, added with `SrtGroupBuilder::add_member` (`add_endpoint(addr)` is the unbound, weight-0 shorthand whose token is its index). `local_addr` is bound as the member's source; `weight` is **libsrt's** (greater is preferred, `0..=MAX_GROUP_MEMBER_WEIGHT` = 32767, carried to the peer in the group handshake); `token` is an opaque caller-chosen id read back on `GroupMemberStats::token`, so a listed member can be matched to its endpoint. `GroupEndpoint::check` refuses what libsrt would refuse for the **whole** group call (source/target family mismatch, weight > 32767) plus a negative token.

libsrt removes a broken member and never brings it back; `SrtGroup::add_member(ep)` re-adds one into the live group (same source, weight, token — what upstream's `testing/testmedia.cpp` does). It is refused (`ConnectionLost`) unless the group still has an Idle or Running member, checked on the I/O thread right before `srt_connect_group`: libsrt counts a *pending* member as healthy, so a member added to a group with no live link would hold the dead group in `Connecting`, sends stalled, instead of letting it break and be redialled whole. Reconnect policy (when, how often, which source) belongs to the consumer — bilbycast-edge's `srt::bond_supervisor`.

Two libsrt group quirks the bridge works around (`epoll_bridge.rs`): `CUDTGroup::addEPoll` raises ERR on a group whose members are all still connecting (`CUDTSocket::broken()` is `!m_bConnected`), so an ERR on a group is fatal only when `srt_getsockstate` (= `getStatus`) agrees; and a memberless group reads `SRTS_BROKEN`, so a group's status is not taken from libsrt until `ConnectGroup` has run. Before both, every caller group was torn down at birth. A third: libsrt keeps a group whose `srt_connect_group` spawned no member (every member refused — e.g. a `local_addr` this host cannot bind), so `SrtGroupBuilder::connect` closes the group it created before returning that error; it leaked the group's two kernel epoll fds and its bridge entry on every failed attempt. That close skips `srt_epoll_remove_usock` for a group still at `Init`, which never joined the bridge's epoll — libsrt logs unsubscribing it as an Error-level "IPE … NOT SUBSCRIBED" line. Two more on the **receive** side, each of which silenced a bonded receiver while its live link still carried every packet: `SRTO_RCVDATA` on a group id is answered from the group's *first listed member* (`CUDTGroup::getOpt`), so a group is read until `srt_recvmsg2` fails instead of being gated on it like a single socket — the gate left the edge-triggered readiness set, never to fire again, once the first-joined link went dark; and a member's TSBPD thread can lose its wake-up while it is out notifying the group (the `InvertedLock` around `updateReadState` in `CUDT::tsbpd`) and then sleep until that member's next ACK, so every live group is also read every `GROUP_RECV_SWEEP` (100 ms) — without it a stream that pauses or ends keeps its last latency-window of packets. And a sixth, on the **connect** side: libsrt can strand a caller member at connect. `groupConnect` starts a member's handshake, reads its status, then writes it Pending (`api.cpp:1712`/`:1747-1751`/`:1822`); when the handshake finishes first (loopback, LAN, a loaded host) that write overwrites `postConnect`'s Idle, nothing ever promotes Pending again, and libsrt never sends on a Pending member — the link carries nothing while every listing (and bilbycast-edge's supervisor) calls it "handshake in progress", and as a group's only connected member it stalls a sender for good with status Connected. The bridge watches every member it spawns into a caller group (`check_stranded_members`, every 100 ms, each member only until it is up; nothing per packet): live `srt_getsockstate(member)` read **before** the listing, then `CONNECTED` while listed Pending (or listed `CONNECTING`) is stranded for good (`postConnect` writes Idle under the group lock before it stores `m_Status`). After a 500 ms grace the same `GroupEndpoint` is connected again: closing the stranded member **first** while another member is up *at the peer* (anything but Broken on a connected socket — another stranded member counts, as its peer lists it live), and **make before break** only while none is — kept until the replacement is up plus the link's latency + 1 s — because closing it first would empty the peer's mirror group, which then fails whole. While none is up but another member is still handshaking (a slow path), the repair **waits** for that handshake to resolve, bounded by that member's connect deadline (its spawn + `SRTO_CONNTIMEO` + 1 s): up, it makes closing first safe; failed, make before break is. The rule is that the peer never lists more members than the bond has, nor none: a bilbycast-edge listener measures redundancy against the most live members a session has had, so an overlap beside any other live member would read as one member more than the bond has and leave one "missing" for good. Decisions within one 100 ms check read each socket's state live, so a member closed earlier in the check is not counted, and a replacement spawned earlier in it counts as handshaking. Also replaced: a member still unresolved past its own `SRTO_CONNTIMEO` + 1 s, and one listed Broken on a connected socket (`groupConnect` can read BROKEN mid-handshake, report the member failed, yet keep it — `connect_group` finds such members by listing the group before and after, and reports them as spawned). That one is at the peer too for as long as the group sends nothing — libsrt closes a Broken member only in its send paths, so in a receive-only group it stays until the bridge replaces it — so it counts as up for another member listed Broken (two such never wait on each other), and any other member **waits** for its replacement instead (`weigh_others`): closing first beside it would leave this side only a Broken member and a handshake, which libsrt reads `CONNECTING`, and left out altogether it let the peer list three members of a bond of two. At most 3 replacements per member, then close-only and the application re-adds; `AddGroupMember` is a no-op `Ok` while a member with that token is Pending/Idle/Running on a live socket, so one handshake per endpoint holds whoever re-adds. Deliberately left alone: a member listed Running in a **broadcast** group (data arrived, so receiving works; libsrt has no per-direction state to show its send side) — a backup group's Running member is re-checked at 1 Hz, since a keepalive lists it Pending again. Only caller groups: on a listener's mirror libsrt marks the socket connected *before* writing Idle, so the test is unsound there (and libsrt does not strand those). Warn-level log, no event; `stranded_member_repairs()` (doc-hidden) counts real occurrences (stranded, listed Broken on a connected socket, or unresolved past the connect timeout) and `SrtGroup::test_strand_member` drives the repair in tests — it exists only with the `test-hooks` feature, which `srt-transport`'s self dev-dependency turns on for `cargo test` / `cargo clippy --all-targets` and no consumer build carries. Re-check the cited libsrt lines on every libsrt bump. `tests/group_members.rs` drives all of this over loopback (Linux for the distinct-source cases).

### API Compatibility

The shared half of the public API mirrors bilbycast-srt; the bonding half has no counterpart there, so swapping the edge's Cargo.toml path dependencies back to bilbycast-srt does not compile (edge issue #102):
- `SrtSocket` / `SrtSocketBuilder` — same methods (30+ builder options)
- `SrtListener` / `SrtListenerBuilder` — same accept/bind/access_control pattern
- `SrtStats` — identical 80+ field struct
- `SrtError`, `RejectReason` — identical enums
- `AccessControl` trait — same signature

## Key Design Constraints

1. **All libsrt calls on the I/O thread** — never call srt_* from Tokio tasks
2. **Channel-based communication only** — IoCommand enum dispatched by the I/O thread loop
3. **Vendored libsrt by default** — ensures v1.5.7 with bonding and AEAD support. **Do not pin
   back**: the last two releases are both security releases, and each fixes something reachable
   pre-authentication on a public SRT listener.
   * v1.5.6 patches CVE-2026-55869 (pre-auth KMREQ/KMRSP stack-based buffer overflow, CVSS 9.1)
     and CVE-2026-55868 (forged-KMREQ encryption-state downgrade letting a receiver accept
     unencrypted data, CVSS 9.1). Both affect every version <= 1.5.5.
   * v1.5.7 (upstream #3359, #3323) hardens control-packet handling and fixes two FEC receive-path
     memory errors. The one that reaches us: `FECFilterBuiltin::ClipData` XOR'd a received packet
     into a buffer sized from our OWN `SRTO_PAYLOADSIZE`, with no bound — so a peer sending larger
     packets than we are configured for wrote past the end of the heap allocation, on any SRT
     input with a `packet_filter` set. Nothing negotiates payload size in the handshake, and
     bilbycast-edge lets an operator set it anywhere in 188-1456 on either end, so a mismatched
     pair was reachable with ordinary config. v1.5.7 truncates instead: the FEC group then fails
     to rebuild, which is the right failure for a mismatched pair.
4. **API superset, not a drop-in** — the shared socket / listener / stats surface must stay mirror-compatible with bilbycast-srt (a divergence there has
   bitten the edge before), but the socket-group bonding surface is libsrt-only and bilbycast-edge references it with no feature gate
   (`src/srt/connection.rs`, `src/engine/output_srt.rs`, `src/engine/input_srt.rs`). bilbycast-srt is therefore **not** substitutable in the edge today —
   restoring that would mean feature-gating the edge's entire bonding surface. See edge issue #102.

## Default `max_bw = -1` (unlimited send pacing)

`SrtConfig::default()` sets `max_bw = -1` rather than libsrt's Live-transtype
default of `0`. `max_bw = 0` tells libsrt to pace the sender "relative to
`input_bw`", but since we also leave `input_bw = 0`, libsrt falls back to
its internal input-bandwidth *estimator*. The estimator is conservative
for the first ~1 s and cannot keep up with a bursty upstream source (the
typical `ffmpeg -re` file read, a camera emptying a kernel buffer on
session start, etc.). When the burst outruns the pacer, libsrt holds
packets in the send buffer past `SNDDROPDELAY` (= latency + 10 ms) and
drops them at the sender — the receiver never sees them and logs
`RCV-DROPPED N packet(s). Packet seqno %X delayed for ~700 ms`.

This is especially harmful under **SMPTE 2022-7 redundancy**, because
both legs share the same process and the same bottleneck, so losses
correlate across legs and the hitless merger has nothing to recover
from. When FEC is layered on top, the gap exceeds the matrix size and
trips `SRT.pf: FEC: IPE: Collecting loss from row ...` inside libsrt's
packet-filter FEC decoder, which further corrupts the output.

Defaulting `max_bw = -1` removes the sender-side pacer entirely. For a
*forwarding gateway* (which is what this wrapper is used for in
`bilbycast-edge`), upstream is already correctly paced — libsrt adding
its own pacing on top only creates warm-up drops. Operators who *do*
want libsrt to pace (e.g. to enforce a per-link cap on a shared WAN
link) can still set an explicit `max_bw` or `input_bw` via the socket
builder / the edge SRT-endpoint config. This matches libsrt's
File-transtype default, not the Live default.

Knobs considered + rejected:
- Raising `send_drop_delay` alone: lets packets queue longer, but if
  the pacer is permanently too slow the queue just grows.
- Raising `send_buffer_size` alone: doesn't help — the buffer wasn't
  the constraint, the pacer was.
- Auto-tuning `input_bw` from measured flow bitrate: the bitrate isn't
  known until several seconds in, which is after the startup burst has
  already done its damage. Would require a separate warm-up path.

### 2022-7 / FEC implications for operators

With `max_bw = -1` the TX-side startup burst no longer drops packets,
which is the precondition for 2022-7 redundancy to deliver any value
and for FEC to stay within its recovery window. Verified 5-of-5
consecutive edge↔edge FEC+2022-7 runs on loopback pass with 0 decode
errors, 0 RCV-DROPPED, 0 FEC-IPE.

Secondary, narrower limitation: on **raw TS** (no RTP header) the edge's
2022-7 SRT input does not merge its legs at all, because the legs share
no sequence number (each SRT connection numbers its packets from its own
ISN, and TS carries only a 4-bit continuity counter per PID). It runs
active-leg failover instead (`RawTsFailover` in
`bilbycast-edge/src/engine/input_srt.rs`): it forwards one leg and
switches to the other only after the forwarded leg has delivered nothing
for 50 ms. A raw-TS pair therefore protects only against a leg failing
outright: a packet the forwarded leg loses past TSBPD is not filled from
the other leg, and a failover skips or repeats some of the stream. For
hitless merging, wrap the upstream in RTP/TS so the merger can key on
the RTP sequence number both legs carry. (Until 2026-05 the
edge keyed raw TS on a per-leg synthetic packet counter, which this
paragraph described until 2026-10; that path is gone.) Reference:
`bilbycast-edge/docs/configuration-guide.md`, "Raw TS 2022-7".
