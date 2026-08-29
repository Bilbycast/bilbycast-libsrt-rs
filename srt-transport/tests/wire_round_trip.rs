// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Payload survives a real SRT handshake — plain, encrypted, and FEC-filtered.
//!
//! # Why this exists
//!
//! This crate had exactly one integration test, and it stops at "the handshake
//! was accepted". Nothing anywhere proved that *bytes* cross a libsrt
//! connection unaltered — so a vendored-libsrt bump could change the wire and
//! every suite in the monorepo would still be green. `cargo test` in
//! bilbycast-edge is 4309 unit tests and not one of them opens an SRT socket.
//!
//! That gap was found bumping libsrt v1.5.6 -> v1.5.7, a security release whose
//! diff lands squarely on the paths this exercises: `srtcore/handshake.cpp` and
//! `crypto.h` (the encrypted case), `srtcore/fec.cpp` (~176 lines, the filtered
//! case), and `srtcore/queue.cpp` + `packet.h` (every case — that is where the
//! new control-packet validation from upstream #3323 sits). A hardening patch
//! that rejects a control message it used to accept would break a legitimate
//! peer here and nowhere else in CI.
//!
//! # Why `harness = false`
//!
//! Same reason as `listener_access_control.rs`, whose module docs carry the
//! detail: `srt_bind` starts libsrt's worker threads, `srt_cleanup()` never
//! runs (the startup guard is a `static OnceLock`, and statics are not
//! dropped), and the teardown race SIGSEGVs the process *after* the assertions
//! have passed. Owning `main` and finishing with `libc::_exit(0)` means a green
//! run is a real green run, while a failed assertion still panics out red.

use std::io::Write;
use std::time::Duration;

use srt_protocol::config::KeySize;
use srt_protocol::error::SrtError;
use srt_transport::{SrtListener, SrtListenerBuilder, SrtSocket, SrtSocketBuilder};

/// One live-mode message, filled with a tag-dependent pattern.
///
/// 1200 bytes, deliberately under the 1316-byte `SRTO_PAYLOADSIZE` this wrapper
/// pins: a live-mode send is ONE message and libsrt refuses one larger than the
/// payload size. Several of these are sent per case so the test still crosses
/// packet boundaries and would notice a reordering or delivery regression.
fn payload(tag: u8, seq: u8) -> Vec<u8> {
    (0..1200u32).map(|i| (i as u8) ^ tag ^ seq).collect()
}

/// How many messages each case pushes through.
const MESSAGES: u8 = 8;

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(payload_survives_a_plain_connection());
    println!("test payload_survives_a_plain_connection ... ok");

    rt.block_on(payload_survives_an_encrypted_connection());
    println!("test payload_survives_an_encrypted_connection ... ok");

    rt.block_on(a_wrong_passphrase_is_refused());
    println!("test a_wrong_passphrase_is_refused ... ok");

    rt.block_on(payload_survives_a_fec_filtered_connection());
    println!("test payload_survives_a_fec_filtered_connection ... ok");

    println!("\ntest result: ok. 4 passed; 0 failed");
    let _ = std::io::stdout().flush();

    // Leave before the C++ static destructors run. See the module docs.
    unsafe { libc::_exit(0) };
}

/// Drive one listener/caller pair and return what the listener received.
///
/// `configure` is applied to BOTH ends, because every option under test here
/// (passphrase, packet filter) has to agree across the handshake — applying it
/// to one side is a different test, and one of the cases below does exactly
/// that on purpose.
async fn round_trip(
    listener_cfg: impl FnOnce(SrtListenerBuilder) -> SrtListenerBuilder,
    caller_cfg: impl FnOnce(SrtSocketBuilder) -> SrtSocketBuilder + Send + 'static,
    tag: u8,
) -> Result<Vec<Vec<u8>>, String> {
    let mut listener = listener_cfg(SrtListener::builder().live_mode())
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .map_err(|e| format!("listener bind: {e:?}"))?;
    let addr = listener.local_addr();

    // The receiver tells the sender when it has everything. Closing on a timer
    // instead raced the teardown against delivery, and a dropped caller socket
    // surfaces as `ConnectionLost` on the read — a rig failure that reads
    // exactly like a wire failure, which is the worst kind of test.
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let sender = tokio::spawn(async move {
        let sock = caller_cfg(
            SrtSocket::builder()
                .live_mode()
                .connect_timeout(Duration::from_secs(8)),
        )
        .connect(addr)
        .await?;
        for seq in 0..MESSAGES {
            sock.send(&payload(tag, seq)).await?;
            // Live mode drops rather than queues, so pace inside the pacer.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let _ = done_rx.await;
        Ok::<(), SrtError>(())
    });

    let accepted = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .map_err(|_| "listener never accepted".to_string())?
        .map_err(|e| format!("accept: {e:?}"))?;

    let mut got = Vec::new();
    for seq in 0..MESSAGES {
        let msg = tokio::time::timeout(Duration::from_secs(5), accepted.recv_bytes())
            .await
            .map_err(|_| format!("message {seq} never arrived"))?
            .map_err(|e| format!("recv: {e:?}"))?;
        got.push(msg.to_vec());
    }

    let _ = done_tx.send(());
    let send_result = sender.await.map_err(|e| format!("sender panicked: {e}"))?;
    send_result.map_err(|e| format!("send: {e:?}"))?;

    Ok(got)
}

/// Every message, in order, byte for byte.
fn expected(tag: u8) -> Vec<Vec<u8>> {
    (0..MESSAGES).map(|seq| payload(tag, seq)).collect()
}

/// The baseline: bytes in, same bytes out, no options at all.
async fn payload_survives_a_plain_connection() {
    let got = round_trip(|l| l, |c| c, 0x5a)
        .await
        .expect("plain round trip");
    assert_eq!(got, expected(0x5a), "payload came back altered on a plain link");
}

/// AES-256 both ends. Exercises the KM exchange, which is where v1.5.7's
/// crypto and handshake changes live.
async fn payload_survives_an_encrypted_connection() {
    let got = round_trip(
        |l| l.encryption("a-shared-passphrase", KeySize::AES256),
        |c| c.encryption("a-shared-passphrase", KeySize::AES256),
        0xa5,
    )
    .await
    .expect("encrypted round trip");
    assert_eq!(
        got,
        expected(0xa5),
        "payload came back altered over an encrypted link"
    );
}

/// A mismatched passphrase must fail, and must fail *closed*.
///
/// The pairing case above only proves agreement works. This is the half that
/// matters: libsrt v1.5.6 fixed a forged-KMREQ downgrade (CVE-2026-55868)
/// where a receiver could be made to accept unencrypted data, so "the wrong
/// key still gets the payload through" is precisely the regression to watch
/// for across any bump.
async fn a_wrong_passphrase_is_refused() {
    let outcome = round_trip(
        |l| l.encryption("the-right-passphrase", KeySize::AES256),
        |c| c.encryption("the-WRONG-passphrase", KeySize::AES256),
        0x3c,
    )
    .await;
    assert!(
        outcome.is_err(),
        "a caller with the wrong passphrase delivered its payload anyway"
    );
}

/// FEC packet filter on both ends.
///
/// FEC interop is one of the two stated reasons the monorepo builds against
/// libsrt rather than the pure-Rust bilbycast-srt, and `srtcore/fec.cpp` is the
/// single largest change in v1.5.7. The filter string is the same grammar
/// bilbycast-edge puts in an SRT input's `packet_filter` config field, so this
/// also pins that the grammar still parses.
async fn payload_survives_a_fec_filtered_connection() {
    let filter = "fec,cols:10,rows:5,layout:staircase,arq:onreq".to_string();
    let got = round_trip(
        {
            let f = filter.clone();
            |l| l.packet_filter(f)
        },
        |c| c.packet_filter(filter),
        0xc3,
    )
    .await
    .expect("FEC round trip");
    assert_eq!(
        got,
        expected(0xc3),
        "payload came back altered over a FEC-filtered link"
    );
}
