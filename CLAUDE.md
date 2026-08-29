# CLAUDE.md — bilbycast-libsrt-rs

## What Is This

Rust wrapper around Haivision's libsrt v1.5.7 for the bilbycast ecosystem. Provides async Tokio-compatible SRT sockets with an API matching the bilbycast-srt pure-Rust implementation, enabling drop-in replacement in bilbycast-edge.

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

### API Compatibility

The public API matches bilbycast-srt exactly so bilbycast-edge only needs to change Cargo.toml path dependencies:
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
4. **Drop-in replacement** — API surface must match bilbycast-srt exactly for edge compatibility

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

Secondary, narrower limitation: the raw-TS dedup path in the edge's
2022-7 merger (`bilbycast-edge/src/engine/input_srt.rs::process_redundant_packet`)
uses a per-leg synthetic counter rather than content. In steady state
both legs deliver packets in the same order (TSBPD enforces that) so
the counters stay aligned and dedup is correct. Counters drift only
if **one leg permanently loses a packet** (past TSBPD) that the other
delivers — after which both legs' Nth-packet-ever are different
content and duplicates can reach the downstream muxer. Under FEC this
is rare because single-packet losses are recovered on each leg before
TSBPD. For asymmetric per-link loss that exceeds the FEC matrix on
one leg only, wrap the upstream in RTP/TS so the merger has a real
sequence number to key on.
