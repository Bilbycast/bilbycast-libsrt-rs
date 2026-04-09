# CLAUDE.md — bilbycast-libsrt-rs

## What Is This

Rust wrapper around Haivision's libsrt v1.5.5-rc.2 for the bilbycast ecosystem. Provides async Tokio-compatible SRT sockets with an API matching the bilbycast-srt pure-Rust implementation, enabling drop-in replacement in bilbycast-edge.

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
- `GroupMode::Balancing` — load balancing

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
3. **Vendored libsrt by default** — ensures v1.5.5-rc.2 with bonding and AEAD support
4. **Drop-in replacement** — API surface must match bilbycast-srt exactly for edge compatibility
