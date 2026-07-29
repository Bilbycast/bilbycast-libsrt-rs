# bilbycast-libsrt-rs

Rust wrapper around [Haivision libsrt](https://github.com/Haivision/srt) v1.5.6 for the [bilbycast](https://github.com/Bilbycast/bilbycast) media transport ecosystem. Provides async Tokio-compatible SRT sockets with an API identical to the [bilbycast-srt](https://github.com/Bilbycast/bilbycast-srt) pure-Rust implementation, enabling drop-in replacement in [bilbycast-edge](https://github.com/Bilbycast/bilbycast-edge).

## Why

bilbycast-srt is a pure-Rust SRT implementation with zero C dependencies, but its FEC and encryption interoperability with third-party SRT devices is incomplete. This wrapper uses Haivision's reference C library directly, giving:

- **Guaranteed interop** with all SRT devices (FEC, encryption, handshake)
- **Native SRT bonding** (Broadcast, Backup group modes)
- **AES-GCM authenticated encryption** via OpenSSL (AEAD API preview)
- **Wire compatibility** verified against libsrt v1.5.6

## Crates

| Crate | Description |
|-------|-------------|
| `libsrt-sys` | Raw FFI bindings via `bindgen`. Vendored libsrt build from `vendor/srt/` (git submodule) via CMake. |
| `srt-protocol` | Pure-Rust data types: config, stats (80+ fields), errors, access control. No C dependency. |
| `srt-transport` | Async transport layer: `SrtSocket`, `SrtListener`, `SrtGroup`. Dedicated I/O thread with `srt_epoll_uwait` bridged to Tokio via lock-free channels. |

## Prerequisites

| Platform | Install |
|----------|---------|
| **Linux** | `apt install cmake libssl-dev clang pkg-config` |
| **macOS** | `brew install cmake openssl` |

A Rust toolchain (stable) is required. Clang is needed by `bindgen` to generate FFI bindings.

## Building

```bash
# Clone with submodules (vendored libsrt source)
git clone --recursive https://github.com/Bilbycast/bilbycast-libsrt-rs.git
cd bilbycast-libsrt-rs

# Build (vendored libsrt, default)
cargo build

# Build with system-installed libsrt instead
cargo build --features libsrt-sys/system-libsrt

# Point to a custom libsrt install
LIBSRT_DIR=/path/to/libsrt cargo build
```

## Architecture

All libsrt C API calls run on a single dedicated OS thread (`srt-io`). Tokio async tasks communicate with it via lock-free channels — no mutex on the data path:

```
Tokio tasks  <-- mpsc / oneshot -->  I/O Thread (srt_epoll_uwait)  <-- C API -->  libsrt
```

- All sockets are non-blocking (`SRTO_RCVSYN=false`, `SRTO_SNDSYN=false`)
- Received data flows through `mpsc::UnboundedSender` (no backpressure on libsrt)
- One global I/O thread per process (`OnceLock` singleton)
- libsrt sockets are not thread-safe — the single-thread model eliminates races

### SRT Bonding

Native bonding via libsrt's socket group API:

- **Broadcast** — all links active, deduplication by libsrt (SMPTE 2022-7 style)
- **Backup** — primary/backup with automatic failover

## API Compatibility

The public API is identical to bilbycast-srt. Switching between the two backends in bilbycast-edge requires only changing two path dependencies in `Cargo.toml`:

- `SrtSocket` / `SrtSocketBuilder` — 30+ builder options
- `SrtListener` / `SrtListenerBuilder` — accept, bind, access control
- `SrtGroup` / `SrtGroupBuilder` — bonding (libsrt-rs only)
- `SrtStats` — 80+ field stats struct
- `SrtError`, `RejectReason` — error enums
- `AccessControl` trait — connection acceptance callback

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).

libsrt (vendored in `libsrt-sys/vendor/srt/`) is licensed under the [Mozilla Public License 2.0](https://github.com/Haivision/srt/blob/master/LICENSE).

Copyright (c) 2026 Softside Tech Pty Ltd.
