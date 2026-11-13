//! F2: a bad handshake does not abort the listener.
//! F3: a peer outside the allowlist is rejected and the transfer continues.
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::fd::FromRawFd;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn bbx() -> &'static str {
    env!("CARGO_BIN_EXE_bbx")
}

fn read_port(stdout: &mut impl Read) -> u16 {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 256];
    for _ in 0..200 {
        let n = stdout.read(&mut tmp).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        let s = String::from_utf8_lossy(&buf);
        if let Some(p) = s.lines().find_map(|l| {
            l.strip_prefix("PORT ")
                .and_then(|p| p.split_whitespace().next())
                .and_then(|p| p.parse().ok())
        }) {
            return p;
        }
        if buf.len() > 2048 {
            break;
        }
    }
    panic!("no PORT: {:?}", String::from_utf8_lossy(&buf));
}

struct Tmp(std::path::PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp() -> Tmp {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("bbx_stray_{}_{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Tmp(dir)
}

fn connect_from(local: Ipv4Addr, remote: SocketAddr) -> TcpStream {
    #[repr(C)]
    struct SockAddrV4 {
        family: u16,
        port: u16,
        addr: u32,
        zero: [u8; 8],
    }
    unsafe extern "C" {
        fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
        fn bind(fd: i32, addr: *const SockAddrV4, len: u32) -> i32;
        fn connect(fd: i32, addr: *const SockAddrV4, len: u32) -> i32;
    }
    let fd = unsafe { socket(2, 1, 0) };
    assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
    let local_addr = SockAddrV4 {
        family: 2,
        port: 0,
        addr: u32::from(local).to_be(),
        zero: [0; 8],
    };
    let rc = unsafe { bind(fd, &local_addr, 16) };
    assert!(rc == 0, "bind {local}: {}", std::io::Error::last_os_error());
    let SocketAddr::V4(remote) = remote else {
        panic!("need an IPv4 destination");
    };
    let remote_addr = SockAddrV4 {
        family: 2,
        port: remote.port().to_be(),
        addr: u32::from(*remote.ip()).to_be(),
        zero: [0; 8],
    };
    let rc = unsafe { connect(fd, &remote_addr, 16) };
    assert!(
        rc == 0,
        "connect {remote}: {}",
        std::io::Error::last_os_error()
    );
    unsafe { TcpStream::from_raw_fd(fd) }
}

fn clear_peer_env(cmd: &mut Command) {
    cmd.env_remove("BBX_PEER_ALLOW");
    cmd.env_remove("BBX_PEER_DEFAULT");
    cmd.env_remove("SSH_CONNECTION");
    cmd.env_remove("BBX_IO_TIMEOUT_SECS");
}

#[test]
fn garbage_and_silent_then_source_completes() {
    let dir = tmp();
    let src = dir.0.join("in.bin");
    let dst = dir.0.join("out.bin");
    let body = vec![7u8; 32_000];
    std::fs::write(&src, &body).unwrap();

    let mut sink = Command::new(bbx());
    clear_peer_env(&mut sink);
    let mut sink = sink
        .args([
            "sink",
            "-l",
            "127.0.0.1:0",
            "-o",
            dst.to_str().unwrap(),
            "-s",
            "1",
            "-E",
            "-C",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let port = read_port(sink.stdout.as_mut().unwrap());
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

    {
        let mut garbage = TcpStream::connect(addr).unwrap();
        garbage.write_all(&[0xff, 0xff, 0xff, 0xff]).unwrap();
    }
    let _silent = TcpStream::connect(addr).unwrap();
    thread::sleep(Duration::from_millis(200));

    let mut source = Command::new(bbx());
    clear_peer_env(&mut source);
    let source = source
        .args([
            "source",
            "-a",
            &format!("127.0.0.1:{port}"),
            "-i",
            src.to_str().unwrap(),
            "-s",
            "1",
            "-E",
            "-C",
        ])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let source_out = source.wait_with_output().unwrap();
    let sink_out = sink.wait_with_output().unwrap();
    let sink_err = String::from_utf8_lossy(&sink_out.stderr);
    assert!(
        source_out.status.success(),
        "source: {}",
        String::from_utf8_lossy(&source_out.stderr)
    );
    assert!(sink_out.status.success(), "sink: {sink_err}");
    assert!(sink_err.contains("rejected"), "{sink_err}");
    assert_eq!(std::fs::read(&dst).unwrap(), body);
}

#[test]
fn flood_of_bad_handshakes_hits_cap() {
    let dir = tmp();
    let dst = dir.0.join("out.bin");
    let mut sink = Command::new(bbx());
    clear_peer_env(&mut sink);
    let mut sink = sink
        .args([
            "sink",
            "-l",
            "127.0.0.1:0",
            "-o",
            dst.to_str().unwrap(),
            "-s",
            "1",
            "-E",
            "-C",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let port = read_port(sink.stdout.as_mut().unwrap());
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    for _ in 0..40 {
        match TcpStream::connect(addr) {
            Ok(mut sock) => {
                let _ = sock.write_all(&[0xff, 0xff, 0xff, 0xff]);
            }
            Err(_) => break,
        }
    }
    let sink_out = sink.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&sink_out.stderr);
    assert!(!sink_out.status.success(), "{err}");
    assert!(err.contains("rejected 32 connections"), "{err}");
}

#[test]
fn non_allowed_peer_does_not_abort() {
    let dir = tmp();
    let src = dir.0.join("in.bin");
    let dst = dir.0.join("out.bin");
    let body = vec![9u8; 16_000];
    std::fs::write(&src, &body).unwrap();
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    let mut sink = Command::new(bbx());
    clear_peer_env(&mut sink);
    let mut sink = sink
        .env("BBX_PEER_ALLOW", "127.0.0.1")
        .args([
            "sink",
            "-l",
            "0.0.0.0:0",
            "-o",
            dst.to_str().unwrap(),
            "-s",
            "1",
            "-e",
            "-C",
            "-k",
            key,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let port = read_port(sink.stdout.as_mut().unwrap());
    // This host does not pick 127.0.0.2 as the source just because the destination is
    // 127.0.0.2. Bind there, then connect to 127.0.0.2, so accept() sees 127.0.0.2.
    let stray_addr = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), port));
    let _stray = connect_from(Ipv4Addr::new(127, 0, 0, 2), stray_addr);
    thread::sleep(Duration::from_millis(100));

    let mut source = Command::new(bbx());
    clear_peer_env(&mut source);
    let source = source
        .args([
            "source",
            "-a",
            &format!("127.0.0.1:{port}"),
            "-i",
            src.to_str().unwrap(),
            "-s",
            "1",
            "-e",
            "-C",
            "-k",
            key,
        ])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let source_out = source.wait_with_output().unwrap();
    let sink_out = sink.wait_with_output().unwrap();
    let sink_err = String::from_utf8_lossy(&sink_out.stderr);
    assert!(
        source_out.status.success(),
        "source: {}",
        String::from_utf8_lossy(&source_out.stderr)
    );
    assert!(sink_out.status.success(), "sink: {sink_err}");
    assert!(sink_err.contains("127.0.0.2"), "{sink_err}");
    assert!(sink_err.contains("BBX_PEER_ALLOW=any"), "{sink_err}");
    assert_eq!(std::fs::read(&dst).unwrap(), body);
}
