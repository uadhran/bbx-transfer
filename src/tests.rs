//! In-crate unit tests for internal helpers.
use std::io::Write;

use crate::cli::{parse_key, parse_port_range};
use crate::commands::{is_remote_spec, split_host_path};
use crate::crypto::{aead_decrypt, aead_encrypt, derive_aead_key, frame_aad, gen_key, hex, stream_id_tag};
use crate::engine::sink_work_path;
use crate::net::{
    accept_streams, bind_ephemeral, cleartext_allowed, ensure_local_peer_default, peer_allowlist,
    split_listen_spec, validate_advertise,
};
use crate::ssh::{
    feed_stderr_scan, finish_agent, release_relay, relay_stderr, ssh_spawn, SshAgent,
    OLD_AGENT_MARK, OLD_AGENT_MSG, STDERR_RELAY_DRAIN,
};
use crate::tree::{dest_path_has_symlink, is_safe_rel, parse_find_print0, walk_local_files};
use crate::util::split_ranges;


#[test]
fn ranges_cover_file() {
    let r = split_ranges(100, 3);
    assert_eq!(r.iter().map(|(a, b)| b - a).sum::<u64>(), 100);
}

#[test]
fn key_roundtrip() {
    let k = gen_key();
    let h = hex(&k);
    assert_eq!(parse_key(&h).unwrap(), k);
}

#[test]
fn derive_aead_unique_per_salt() {
    let psk = [0x42u8; 32];
    let s1 = [1u8; 32];
    let s2 = [2u8; 32];
    let a = derive_aead_key(&psk, &s1);
    let b = derive_aead_key(&psk, &s2);
    let a2 = derive_aead_key(&psk, &s1);
    assert_ne!(a, b, "different salts must yield different AEAD keys");
    assert_eq!(a, a2, "same psk+salt must be deterministic");
    assert_ne!(a, psk, "derived key must not equal raw PSK");
}

#[test]
fn stream_id_mac_binds_psk() {
    let psk = [7u8; 32];
    let t0 = stream_id_tag(&psk, 0);
    let t1 = stream_id_tag(&psk, 1);
    let t0b = stream_id_tag(&psk, 0);
    assert_ne!(t0, t1);
    assert_eq!(t0, t0b);
    let other = stream_id_tag(&[8u8; 32], 0);
    assert_ne!(t0, other);
}

#[test]
fn aead_aad_mismatch_fails() {
    let k = derive_aead_key(&[1u8; 32], &[2u8; 32]);
    let aad_ok = frame_aad(2, 100, 4, 0, &[2u8; 32]);
    let aad_bad = frame_aad(2, 101, 4, 0, &[2u8; 32]);
    let ct = aead_encrypt(&k, 0, 0, b"hello", &aad_ok).unwrap();
    assert!(aead_decrypt(&k, 0, 0, &ct, &aad_ok).is_ok());
    assert!(aead_decrypt(&k, 0, 0, &ct, &aad_bad).is_err());
}

#[test]
fn cleartext_loopback_ok() {
    assert!(cleartext_allowed("127.0.0.1:9").is_ok());
    assert!(cleartext_allowed("127.0.0.1").is_ok());
}

#[test]
fn advertise_rejects_metachar() {
    assert!(validate_advertise("10.0.0.1").is_ok());
    assert!(validate_advertise("host.example").is_ok());
    assert!(validate_advertise("evil;rm -rf").is_err());
    assert!(validate_advertise("a b").is_err());
    assert!(validate_advertise("").is_err());
}

#[test]
fn remote_spec() {
    assert!(is_remote_spec("user@host:/tmp/x"));
    assert!(!is_remote_spec("/tmp/x"));
    assert!(is_remote_spec("[::1]:/tmp/x"));
    assert!(is_remote_spec("user@[2001:db8::1]:/data"));
    assert!(!is_remote_spec("C:/windows/path"));
    assert_eq!(
        split_host_path("[::1]:/tmp/x").unwrap(),
        ("[::1]", "/tmp/x")
    );
    assert_eq!(
        split_host_path("user@[::1]:/tmp/x").unwrap(),
        ("user@[::1]", "/tmp/x")
    );
}

#[test]
fn rejects_unsafe_remote_paths() {
    assert!(is_safe_rel("a/b/c.txt"));
    assert!(is_safe_rel("root.bin"));
    assert!(!is_safe_rel("/etc/passwd"));
    assert!(!is_safe_rel("../secrets"));
    assert!(!is_safe_rel("a/../../b"));
    assert!(!is_safe_rel(""));
}

#[test]
fn parse_find_print0_keeps_spaces_and_newlines() {
    // "a b.txt\0dir/\nfile.txt\0" — second name contains a newline
    let mut raw = Vec::new();
    raw.extend_from_slice(b"./a b.txt\0");
    raw.extend_from_slice(b"./dir/\nfile.txt\0");
    let files = parse_find_print0(&raw);
    assert_eq!(files.len(), 2);
    assert!(files.iter().any(|f| f == "a b.txt"));
    assert!(files.iter().any(|f| f == "dir/\nfile.txt"));
    // no trim of internal spaces
    assert!(!files.iter().any(|f| f == "a b.txt ".trim() && f.ends_with(' ')));
}

#[test]
#[cfg(unix)]
fn dest_symlink_component_detected() {
    let dir = std::env::temp_dir().join(format!("bbx_sym_{}", std::process::id()));
    let outside = std::env::temp_dir().join(format!("bbx_sym_out_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    assert!(dest_path_has_symlink(&dir, "link/file").unwrap());
    assert!(!dest_path_has_symlink(&dir, "safe/file").unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn sink_work_path_temp_for_fresh() {
    let (p, is_temp) = sink_work_path("/tmp/bbx_dest.bin", 0).unwrap();
    assert!(is_temp);
    assert!(p.contains(".bbx.") && p.ends_with(".tmp"));
    let (p2, is_temp2) = sink_work_path("/tmp/bbx_dest.bin", 100).unwrap();
    assert!(!is_temp2);
    assert_eq!(p2, "/tmp/bbx_dest.bin");
}

#[test]
fn walk_lists_nested_files() {
    let dir = std::env::temp_dir().join(format!("bbx_walk_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("a/b")).unwrap();
    std::fs::write(dir.join("a/b/c.txt"), b"hi").unwrap();
    std::fs::write(dir.join("root.bin"), b"x").unwrap();
    let files = walk_local_files(&dir).unwrap();
    let rels: Vec<_> = files.iter().map(|(_, r)| r.as_str()).collect();
    assert!(rels.contains(&"a/b/c.txt") || rels.iter().any(|r| r.ends_with("c.txt")));
    assert!(rels.iter().any(|r| r.ends_with("root.bin")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn port_range_parse() {
    assert_eq!(parse_port_range("50000-50010").unwrap(), (50000, 50010));
    assert_eq!(parse_port_range("1000:1001").unwrap(), (1000, 1001));
    assert!(parse_port_range("0-10").is_err());
    assert!(parse_port_range("20-10").is_err());
}

#[test]
fn bind_in_range() {
    let l = bind_ephemeral(Some((45000, 45050))).unwrap();
    let p = l.local_addr().unwrap().port();
    assert!((45000..=45050).contains(&p));
}

#[test]
fn listen_spec_split() {
    assert_eq!(split_listen_spec("0.0.0.0:0").unwrap(), ("0.0.0.0".into(), 0));
    assert_eq!(split_listen_spec("127.0.0.1:9").unwrap(), ("127.0.0.1".into(), 9));
}

fn without_peer_env<T>(f: impl FnOnce() -> T) -> T {
    let prev_allow = std::env::var("BBX_PEER_ALLOW").ok();
    let prev_default = std::env::var("BBX_PEER_DEFAULT").ok();
    unsafe {
        std::env::remove_var("BBX_PEER_ALLOW");
        std::env::remove_var("BBX_PEER_DEFAULT");
    }
    let out = f();
    restore_env("BBX_PEER_ALLOW", prev_allow);
    restore_env("BBX_PEER_DEFAULT", prev_default);
    out
}

fn restore_env(key: &str, prev: Option<String>) {
    unsafe {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
}

#[test]
fn accept_stops_when_agent_gone_and_idle() {
    without_peer_env(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let start = std::time::Instant::now();
        let mut gone = || Some("remote source exited exit status: 1".to_string());
        let err = accept_streams(&listener, 2, 64 * 1024, "sink", None, Some(&mut gone))
            .unwrap_err();
        let elapsed = start.elapsed();
        assert!(err.contains("remote source exited exit status: 1"), "{err}");
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
    });
}

#[test]
fn accept_queued_streams_when_agent_already_gone() {
    without_peer_env(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let streams = 3usize;
        let mut clients = Vec::new();
        for id in 0..streams {
            let mut c = std::net::TcpStream::connect(addr).unwrap();
            c.write_all(&(id as u32).to_le_bytes()).unwrap();
            clients.push(c);
        }
        let mut calls = 0u32;
        let mut gone = || {
            calls += 1;
            Some("remote source exited exit status: 0".to_string())
        };
        let conns =
            accept_streams(&listener, streams, 64 * 1024, "sink", None, Some(&mut gone)).unwrap();
        assert_eq!(conns.len(), streams);
        assert_eq!(calls, 0, "queued connections must be accepted without polling the agent");
    });
}

#[test]
fn local_allowlist_loopback_advertise() {
    let prev_allow = std::env::var("BBX_PEER_ALLOW").ok();
    let prev_default = std::env::var("BBX_PEER_DEFAULT").ok();
    let prev_adv = std::env::var("BBX_ADVERTISE").ok();
    unsafe {
        std::env::remove_var("BBX_PEER_ALLOW");
        std::env::remove_var("BBX_PEER_DEFAULT");
    }
    let cases = [
        ("user@127.0.0.1", "203.0.113.9", vec!["127.0.0.1", "203.0.113.9"]),
        ("user@127.0.0.1", "files.example", vec!["127.0.0.1"]),
        ("user@192.0.2.10", "203.0.113.9", vec!["192.0.2.10"]),
    ];
    let mut got = Vec::new();
    for (remote, advertise, expect) in cases {
        unsafe {
            std::env::remove_var("BBX_PEER_DEFAULT");
            std::env::set_var("BBX_ADVERTISE", advertise);
        }
        ensure_local_peer_default(remote, true).unwrap();
        let allow = peer_allowlist().unwrap().expect("allowlist");
        let expect: Vec<std::net::IpAddr> = expect.into_iter().map(|s| s.parse().unwrap()).collect();
        got.push((allow, expect, remote, advertise));
    }
    restore_env("BBX_PEER_ALLOW", prev_allow);
    restore_env("BBX_PEER_DEFAULT", prev_default);
    restore_env("BBX_ADVERTISE", prev_adv);
    for (allow, expect, remote, advertise) in got {
        assert_eq!(allow, expect, "{remote} advertise={advertise}");
    }
}

#[test]
fn old_agent_mark_survives_split_reads() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let saw = AtomicBool::new(false);
    let mut carry = Vec::new();
    let text = b"bbx: unknown flag --key-stdin\n";
    for &b in text {
        feed_stderr_scan(&mut carry, &[b], &saw);
    }
    assert!(saw.load(Ordering::Relaxed), "one-byte reads must still match");

    let saw = AtomicBool::new(false);
    let mut carry = Vec::new();
    feed_stderr_scan(&mut carry, b"bbx: unknown flag --key-stdi", &saw);
    assert!(!saw.load(Ordering::Relaxed));
    feed_stderr_scan(&mut carry, b"n\n", &saw);
    assert!(saw.load(Ordering::Relaxed));

    let saw = AtomicBool::new(false);
    let mut carry = Vec::new();
    feed_stderr_scan(&mut carry, b"bbx: rejected something else\n", &saw);
    assert!(!saw.load(Ordering::Relaxed));
    assert_eq!(OLD_AGENT_MARK, b"unknown flag --key-stdin");
}

#[test]
fn stderr_relay_stops_when_pipe_stays_open() {
    use std::os::unix::io::FromRawFd;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let read = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let _write = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    let saw = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(true));
    let tail = Arc::new(Mutex::new(Vec::new()));
    let start = std::time::Instant::now();
    relay_stderr(read, saw, done, tail);
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(100),
        "drain bound was not applied: {elapsed:?}"
    );
    assert!(
        elapsed < STDERR_RELAY_DRAIN + std::time::Duration::from_secs(1),
        "relay blocked past the drain bound: {elapsed:?}"
    );
}

#[test]
fn shutdown_relay_detaches_when_thread_blocks() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    let done = AtomicBool::new(false);
    let stop = Arc::new(AtomicBool::new(false));
    let started = Arc::new(AtomicBool::new(false));
    let mut relay = Some(thread::spawn({
        let stop = Arc::clone(&stop);
        let started = Arc::clone(&started);
        move || {
            started.store(true, Ordering::Relaxed);
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }));
    while !started.load(Ordering::Relaxed) {
        thread::sleep(std::time::Duration::from_millis(1));
    }
    let start = std::time::Instant::now();
    release_relay(&mut relay, &done);
    let elapsed = start.elapsed();
    stop.store(true, Ordering::Relaxed);
    assert!(relay.is_none());
    assert!(
        elapsed >= std::time::Duration::from_millis(100),
        "detached before the drain bound: {elapsed:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "release blocked past the drain bound: {elapsed:?}"
    );
}

#[test]
fn key_write_after_exit_reports_ssh_status() {
    use std::process::{Command, Stdio};
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("echo 'ssh: Connection refused' >&2; exit 255")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut agent = SshAgent::start(child, stderr);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while agent.child.try_wait().unwrap().is_none() {
        assert!(std::time::Instant::now() < deadline, "helper did not exit");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let err = agent.write_key(&[0x11; 32]).unwrap_err();
    assert!(err.contains("255"), "{err}");
    assert!(err.contains("Connection refused"), "{err}");
    assert!(!err.to_lowercase().contains("broken pipe"), "{err}");
}

#[test]
fn old_remote_key_stdin_is_upgrade_error() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!(
        "bbx-fake-ssh-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let ssh = dir.join("ssh");
    std::fs::write(
        &ssh,
        "#!/bin/sh\ncat >/dev/null\necho 'bbx: unknown flag --key-stdin' >&2\nexit 1\n",
    )
    .unwrap();
    let mut perm = std::fs::metadata(&ssh).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&ssh, perm).unwrap();
    let prev = std::env::var("PATH").unwrap_or_default();
    unsafe {
        std::env::set_var("PATH", format!("{}:{}", dir.display(), prev));
    }
    let result = ssh_spawn("host", "bbx source --key-stdin", Some(&[0x22; 32])).and_then(|mut agent| {
        finish_agent(&mut agent, Ok(()), "remote")
    });
    unsafe {
        std::env::set_var("PATH", &prev);
    }
    let _ = std::fs::remove_dir_all(&dir);
    let err = result.unwrap_err();
    assert_eq!(err, OLD_AGENT_MSG);
}
