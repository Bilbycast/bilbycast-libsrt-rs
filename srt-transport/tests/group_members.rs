// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Bonded caller groups (`SrtGroup`) end to end against a group listener:
//! media crosses, each member's source, weight and token reach libsrt, and a
//! broken member can be brought back into the live group.
//!
//! # Why this exists
//!
//! Nothing ever proved a caller group carried media, and it did not: libsrt
//! raises ERR readiness on a group whose members are all still connecting
//! when the group is added to an epoll, and the bridge adds it at exactly
//! that moment, so every caller group was marked `Broken` at birth.
//!
//! libsrt also removes a broken member and leaves reconnecting it to the
//! application (vendored `docs/features/socket-groups.md`). This wrapper gave
//! the application no way to do that, so a bonded edge that lost one link ran
//! on the rest with no redundancy until every link failed (bilbycast-edge
//! #203). And every member was prepared with a null source address and
//! libsrt's default weight, so a configured per-member source and weight did
//! nothing (bilbycast-edge #184). Every case below fails on the code before
//! those fixes — the member cases do not even compile against it.
//!
//! # Why `harness = false`
//!
//! Same reason as `listener_access_control.rs`, whose module docs carry the
//! detail: these open real SRT sockets, and the process must leave with
//! `libc::_exit(0)` before libsrt's C++ statics are torn down.

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use srt_protocol::error::SrtError;
use srt_transport::{
    GroupEndpoint, GroupMemberStats, GroupMode, MemberStatus, SocketStatus, SrtGroup, SrtListener,
    SrtSocket,
};
use tokio::net::UdpSocket;

/// Generous: libsrt's own timers (peer idle 1 s here, connect timeout 3 s,
/// the bridge's ~1 s state poll) decide how fast things move, and a loaded
/// CI host should not turn a slow pass into a failure.
const DEADLINE: Duration = Duration::from_secs(10);

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let mut passed = 0;

    rt.block_on(a_caller_group_survives_its_own_connect_and_carries_media_both_ways());
    println!("test a_caller_group_survives_its_own_connect_and_carries_media_both_ways ... ok");
    passed += 1;

    // Distinct loopback source IPs: Linux routes all of 127/8 to `lo`;
    // macOS's `lo0` has only 127.0.0.1.
    #[cfg(target_os = "linux")]
    {
        rt.block_on(a_member_binds_its_source_address());
        println!("test a_member_binds_its_source_address ... ok");
        passed += 1;

        rt.block_on(weight_and_token_reach_both_ends());
        println!("test weight_and_token_reach_both_ends ... ok");
        passed += 1;
    }

    rt.block_on(a_broken_member_is_re_added_and_media_never_gaps(false));
    println!("test a_broken_member_is_re_added_and_media_never_gaps ... ok");
    passed += 1;

    rt.block_on(a_broken_member_is_re_added_and_media_never_gaps(true));
    println!("test a_member_with_a_fixed_source_port_is_re_added_and_media_never_gaps ... ok");
    passed += 1;

    rt.block_on(add_member_on_a_closed_group_is_refused());
    println!("test add_member_on_a_closed_group_is_refused ... ok");
    passed += 1;

    rt.block_on(add_member_with_an_unbindable_source_reports_the_bind_error());
    println!("test add_member_with_an_unbindable_source_reports_the_bind_error ... ok");
    passed += 1;

    rt.block_on(losing_every_member_still_tears_the_group_down());
    println!("test losing_every_member_still_tears_the_group_down ... ok");
    passed += 1;

    println!("\ntest result: ok. {passed} passed; 0 failed");
    let _ = std::io::stdout().flush();

    // Leave before the C++ static destructors run. See the module docs.
    unsafe { libc::_exit(0) };
}

// ── Rig ─────────────────────────────────────────────────────────────────

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A loopback UDP relay in front of `target` that can be told to drop
/// everything, in both directions: a link that goes dark without closing.
///
/// Each distinct client address gets its own upstream socket, so a re-added
/// member that leaves from a new source port is relayed as a new peer.
struct Blackhole {
    addr: SocketAddr,
    dropping: Arc<AtomicBool>,
}

impl Blackhole {
    async fn start(target: SocketAddr) -> Self {
        let down = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = down.local_addr().unwrap();
        let dropping = Arc::new(AtomicBool::new(false));
        let drop_flag = dropping.clone();
        tokio::spawn(async move {
            let mut upstreams: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, client)) = down.recv_from(&mut buf).await else {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                };
                if drop_flag.load(Ordering::SeqCst) {
                    continue;
                }
                let up = match upstreams.get(&client) {
                    Some(up) => up.clone(),
                    None => {
                        let up = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                        up.connect(target).await.unwrap();
                        let (back, down, drop_flag) = (up.clone(), down.clone(), drop_flag.clone());
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 2048];
                            loop {
                                match back.recv(&mut buf).await {
                                    Ok(n) if !drop_flag.load(Ordering::SeqCst) => {
                                        let _ = down.send_to(&buf[..n], client).await;
                                    }
                                    Ok(_) => {}
                                    // ICMP port-unreachable surfaces here on a
                                    // connected socket; keep relaying.
                                    Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
                                }
                            }
                        });
                        upstreams.insert(client, up.clone());
                        up
                    }
                };
                let _ = up.send(&buf[..n]).await;
            }
        });
        Self { addr, dropping }
    }

    fn set_dropping(&self, on: bool) {
        self.dropping.store(on, Ordering::SeqCst);
    }
}

async fn group_listener() -> SrtListener {
    SrtListener::builder()
        .live_mode()
        .latency(Duration::from_millis(120))
        .peer_idle_timeout(Duration::from_secs(1))
        .group_connect(true)
        .bind(addr("127.0.0.1:0"))
        .await
        .expect("group listener bind")
}

async fn connect_group(mode: GroupMode, members: &[GroupEndpoint]) -> Arc<SrtGroup> {
    let mut b = SrtGroup::builder(mode)
        .live_mode()
        .latency(Duration::from_millis(120))
        .peer_idle_timeout(Duration::from_secs(1))
        .connect_timeout(Duration::from_secs(3));
    for m in members {
        b = b.add_member(*m);
    }
    b.connect().await.expect("group connect")
}

async fn accept(listener: &mut SrtListener) -> SrtSocket {
    tokio::time::timeout(DEADLINE, listener.accept())
        .await
        .expect("listener never accepted the group")
        .expect("accept")
}

/// Idle or Running on a live socket: a member that is carrying, or ready to
/// carry, the group's media.
fn healthy(m: &GroupMemberStats) -> bool {
    matches!(m.member_status, MemberStatus::Idle | MemberStatus::Running) && !terminal(m.socket_status)
}

fn token_healthy(members: &[GroupMemberStats], token: i32) -> bool {
    members.iter().any(|m| m.token == token && healthy(m))
}

/// Poll until `cond` holds on the caller group's members, or panic with
/// `what` and the last listing.
async fn wait_caller(group: &SrtGroup, what: &str, cond: impl Fn(&[GroupMemberStats]) -> bool) {
    let start = Instant::now();
    loop {
        let members = group.member_stats().await;
        if cond(&members) {
            return;
        }
        if start.elapsed() > DEADLINE {
            panic!("caller group never reached: {what}; members: {members:#?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_listener(sock: &SrtSocket, what: &str, cond: impl Fn(&[GroupMemberStats]) -> bool) {
    let start = Instant::now();
    loop {
        let members = sock.member_stats().await;
        if cond(&members) {
            return;
        }
        if start.elapsed() > DEADLINE {
            panic!("listener group never reached: {what}; members: {members:#?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── Cases ───────────────────────────────────────────────────────────────

/// #184(a): a member's source address is bound. Before, both members left
/// from the default source (127.0.0.1 on loopback) whatever was configured.
#[cfg(target_os = "linux")]
async fn a_member_binds_its_source_address() {
    let mut listener = group_listener().await;
    let target = listener.local_addr();
    let mut a = GroupEndpoint::new(target, 0);
    a.local_addr = Some(addr("127.0.0.2:0"));
    let mut b = GroupEndpoint::new(target, 1);
    b.local_addr = Some(addr("127.0.0.3:0"));
    let group = connect_group(GroupMode::Broadcast, &[a, b]).await;
    let accepted = accept(&mut listener).await;

    wait_listener(&accepted, "both members from their own source", |ms| {
        let mut ips: Vec<String> = ms
            .iter()
            .filter(|m| healthy(m))
            .filter_map(|m| m.peer_addr.map(|a| a.ip().to_string()))
            .collect();
        ips.sort();
        ips == ["127.0.0.2", "127.0.0.3"]
    })
    .await;
    wait_caller(&group, "tokens 0 and 1 healthy", |ms| {
        token_healthy(ms, 0) && token_healthy(ms, 1)
    })
    .await;

    let _ = group.close().await;
    let _ = accepted.close().await;
    let _ = listener.close().await;
}

/// #184(b): the weight reaches libsrt on the caller, and travels in the group
/// handshake to the listener's mirror group; the token comes back on the
/// caller's member listing. Before, every member had weight 0 at both ends.
#[cfg(target_os = "linux")]
async fn weight_and_token_reach_both_ends() {
    let mut listener = group_listener().await;
    let target = listener.local_addr();
    let mut primary = GroupEndpoint::new(target, 0);
    primary.local_addr = Some(addr("127.0.0.2:0"));
    primary.weight = 5;
    let mut standby = GroupEndpoint::new(target, 1);
    standby.local_addr = Some(addr("127.0.0.3:0"));
    let group = connect_group(GroupMode::Backup, &[primary, standby]).await;
    let accepted = accept(&mut listener).await;

    wait_caller(&group, "both members healthy", |ms| {
        token_healthy(ms, 0) && token_healthy(ms, 1)
    })
    .await;
    let caller = group.member_stats().await;
    let weight_of = |token| caller.iter().find(|m| m.token == token && healthy(m)).unwrap().weight;
    assert_eq!(weight_of(0), 5, "caller member 0 weight: {caller:#?}");
    assert_eq!(weight_of(1), 0, "caller member 1 weight: {caller:#?}");

    wait_listener(&accepted, "both members with their caller's weight", |ms| {
        let weight_from = |ip: &str| {
            ms.iter()
                .find(|m| healthy(m) && m.peer_addr.is_some_and(|a| a.ip().to_string() == ip))
                .map(|m| m.weight)
        };
        weight_from("127.0.0.2") == Some(5) && weight_from("127.0.0.3") == Some(0)
    })
    .await;

    let _ = group.close().await;
    let _ = accepted.close().await;
    let _ = listener.close().await;
}

/// #203: a member that breaks is re-added into the live group with the same
/// endpoint, and the receiver sees every message exactly once, in order,
/// across the loss and the re-add (broadcast mode: the other member carried
/// everything throughout).
///
/// With `fixed_source_port`, the member is bound to one fixed source
/// `ip:port` and re-added with it while its broken predecessor may still be
/// listed (libsrt keeps a broken member until its buffers drain), so the
/// re-add shares the predecessor's multiplexer.
async fn a_broken_member_is_re_added_and_media_never_gaps(fixed_source_port: bool) {
    let mut listener = group_listener().await;
    let target = listener.local_addr();
    let hole = Blackhole::start(target).await;

    let direct = GroupEndpoint::new(target, 0);
    let mut flaky = GroupEndpoint::new(hole.addr, 1);
    if fixed_source_port {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        flaky.local_addr = Some(probe.local_addr().unwrap());
        drop(probe);
    }
    let group = connect_group(GroupMode::Broadcast, &[direct, flaky]).await;
    let accepted = Arc::new(accept(&mut listener).await);
    wait_caller(&group, "both members healthy", |ms| {
        token_healthy(ms, 0) && token_healthy(ms, 1)
    })
    .await;

    // Numbered messages at 100/s for the whole episode.
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU32::new(0));
    let sender = {
        let (group, stop, sent) = (group.clone(), stop.clone(), sent.clone());
        tokio::spawn(async move {
            let mut seq: u32 = 0;
            while !stop.load(Ordering::SeqCst) {
                let mut msg = vec![0u8; 1200];
                msg[..4].copy_from_slice(&seq.to_be_bytes());
                group.send(&msg).await.expect("group send");
                seq += 1;
                sent.store(seq, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    };
    let receiver = {
        let accepted = accepted.clone();
        tokio::spawn(async move {
            let mut got = Vec::new();
            // Two seconds of silence after the sender stops ends the read.
            while let Ok(Ok(pkt)) = tokio::time::timeout(Duration::from_secs(2), accepted.recv()).await {
                got.push(u32::from_be_bytes(pkt.data[..4].try_into().unwrap()));
            }
            got
        })
    };

    tokio::time::sleep(Duration::from_millis(300)).await;
    hole.set_dropping(true);
    wait_caller(&group, "member 1 lost while member 0 stays up", |ms| {
        token_healthy(ms, 0) && !token_healthy(ms, 1)
            && !ms.iter().any(|m| m.token == 1 && m.member_status == MemberStatus::Pending)
    })
    .await;
    hole.set_dropping(false);

    group.add_member(flaky).await.expect("re-add into a live group");
    wait_caller(&group, "member 1 back", |ms| token_healthy(ms, 0) && token_healthy(ms, 1)).await;
    wait_listener(&accepted, "two live members again", |ms| {
        ms.iter().filter(|m| healthy(m)).count() == 2
    })
    .await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    stop.store(true, Ordering::SeqCst);
    sender.await.unwrap();
    let got = receiver.await.unwrap();
    let total = sent.load(Ordering::SeqCst);
    let expected: Vec<u32> = (0..total).collect();
    assert!(total > 50, "only {total} messages sent");
    assert_eq!(
        got.len(),
        expected.len(),
        "received {} of {total} messages (first missing: {:?})",
        got.len(),
        expected.iter().find(|s| !got.contains(s)),
    );
    assert_eq!(got, expected, "messages duplicated or reordered across the re-add");

    let _ = group.close().await;
    let _ = accepted.close().await;
    let _ = listener.close().await;
}

/// A closed group is never revived by a re-add.
async fn add_member_on_a_closed_group_is_refused() {
    let mut listener = group_listener().await;
    let target = listener.local_addr();
    let ep = GroupEndpoint::new(target, 0);
    let group = connect_group(GroupMode::Broadcast, &[ep]).await;
    let accepted = accept(&mut listener).await;
    wait_caller(&group, "member healthy", |ms| token_healthy(ms, 0)).await;

    group.close().await.unwrap();
    assert_eq!(group.add_member(GroupEndpoint::new(target, 1)).await, Err(SrtError::ConnectionLost));

    let _ = accepted.close().await;
    let _ = listener.close().await;
}

/// A member whose source cannot be bound (TEST-NET-1 is never local) reports
/// the bind failure, not libsrt's catch-all "no member could be spawned"
/// `ConnectionLost` — the reason an operator needs to see.
async fn add_member_with_an_unbindable_source_reports_the_bind_error() {
    let mut listener = group_listener().await;
    let target = listener.local_addr();
    let group = connect_group(GroupMode::Broadcast, &[GroupEndpoint::new(target, 0)]).await;
    let accepted = accept(&mut listener).await;
    wait_caller(&group, "member healthy", |ms| token_healthy(ms, 0)).await;

    let mut ep = GroupEndpoint::new(target, 1);
    ep.local_addr = Some(addr("192.0.2.1:0"));
    let result = group.add_member(ep).await;
    assert!(
        matches!(result, Err(e) if e != SrtError::ConnectionLost),
        "unbindable source reported as {result:?}"
    );
    // The live member is untouched.
    wait_caller(&group, "member 0 still healthy", |ms| token_healthy(ms, 0)).await;

    let _ = group.close().await;
    let _ = accepted.close().await;
    let _ = listener.close().await;
}

/// The all-links-down case stays the whole-group teardown it always was: a
/// re-add is refused once no member is Idle or Running (libsrt would count
/// the new, pending member as healthy and keep the dead group from ever
/// breaking), and the group's `recv` ends so the application redials it.
async fn losing_every_member_still_tears_the_group_down() {
    let mut listener = group_listener().await;
    let target = listener.local_addr();
    let hole_a = Blackhole::start(target).await;
    let hole_b = Blackhole::start(target).await;
    let a = GroupEndpoint::new(hole_a.addr, 0);
    let b = GroupEndpoint::new(hole_b.addr, 1);
    let group = connect_group(GroupMode::Broadcast, &[a, b]).await;
    let accepted = accept(&mut listener).await;
    wait_caller(&group, "both members healthy", |ms| {
        token_healthy(ms, 0) && token_healthy(ms, 1)
    })
    .await;

    hole_a.set_dropping(true);
    hole_b.set_dropping(true);
    let start = Instant::now();
    loop {
        let members = group.member_stats().await;
        if !members.iter().any(healthy) {
            break;
        }
        assert!(start.elapsed() < DEADLINE, "members never broke: {members:#?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        group.add_member(a).await,
        Err(SrtError::ConnectionLost),
        "re-add accepted into a group with no live member"
    );
    let ended = tokio::time::timeout(DEADLINE, group.recv()).await;
    assert!(
        matches!(ended, Ok(Err(_))),
        "group with every member lost did not end its recv: {:?}",
        ended.map(|r| r.map(|p| p.data.len()))
    );

    let _ = group.close().await;
    let _ = accepted.close().await;
    let _ = listener.close().await;
}

fn terminal(s: SocketStatus) -> bool {
    matches!(
        s,
        SocketStatus::Broken | SocketStatus::Closing | SocketStatus::Closed | SocketStatus::NonExist
    )
}

fn message(seq: u32) -> Vec<u8> {
    let mut msg = vec![(seq as u8) ^ 0x5a; 1200];
    msg[..4].copy_from_slice(&seq.to_be_bytes());
    msg
}

const MESSAGES: u32 = 20;

/// A two-member broadcast caller group stays up past the moment the bridge
/// registers it, and every message crosses in both directions.
async fn a_caller_group_survives_its_own_connect_and_carries_media_both_ways() {
    let mut listener = group_listener().await;
    let target = listener.local_addr();
    let group: Arc<SrtGroup> = SrtGroup::builder(GroupMode::Broadcast)
        .live_mode()
        .latency(Duration::from_millis(120))
        .connect_timeout(Duration::from_secs(3))
        .add_endpoint(target)
        .add_endpoint(target)
        .connect()
        .await
        .expect("group connect");
    let accepted = tokio::time::timeout(DEADLINE, listener.accept())
        .await
        .expect("listener never accepted the group")
        .expect("accept");

    // Past the bridge's first ~1 s state poll as well as the epoll add.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!terminal(group.status()), "caller group torn down at birth: {:?}", group.status());

    // Caller -> listener.
    for seq in 0..MESSAGES {
        group.send(&message(seq)).await.expect("caller group send");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for seq in 0..MESSAGES {
        let pkt = tokio::time::timeout(DEADLINE, accepted.recv())
            .await
            .unwrap_or_else(|_| panic!("listener: message {seq} never arrived"))
            .expect("listener recv");
        assert_eq!(pkt.data.as_ref(), message(seq).as_slice(), "listener: message {seq}");
    }

    // Listener -> caller.
    for seq in 0..MESSAGES {
        accepted.send(&message(seq)).await.expect("listener send");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for seq in 0..MESSAGES {
        let pkt = tokio::time::timeout(DEADLINE, group.recv())
            .await
            .unwrap_or_else(|_| panic!("caller group: message {seq} never arrived"))
            .expect("caller group recv");
        assert_eq!(pkt.data.as_ref(), message(seq).as_slice(), "caller group: message {seq}");
    }
    assert!(!terminal(group.status()), "caller group status: {:?}", group.status());

    let _ = group.close().await;
    let _ = accepted.close().await;
    let _ = listener.close().await;
}
