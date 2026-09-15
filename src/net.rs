//! Networking: address policy, binding, dialing/accepting streams, advertise-IP discovery, IO timeouts.

use crate::{CONNECT_TIMEOUT, IO_TIMEOUT_SECS, SID_TAG_LEN};
use crate::crypto::stream_id_tag;
use crate::util::{read_u32, write_u32};
use std::env;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;

/// Cleartext (-E) is loopback-only unless `BBX_ALLOW_CLEAR=1`.
pub(crate) fn cleartext_allowed(hostish: &str) -> Result<(), String> {
    if env::var("BBX_ALLOW_CLEAR").ok().as_deref() == Some("1") {
        return Ok(());
    }
    if host_is_loopback(hostish) {
        return Ok(());
    }
    Err(
        "cleartext (-E) refused on non-loopback; use -e encrypt, or BBX_ALLOW_CLEAR=1 for trusted nets"
            .into(),
    )
}

pub fn host_is_loopback(s: &str) -> bool {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return sa.ip().is_loopback();
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    let h = s.trim_matches(|c| c == '[' || c == ']');
    matches!(h, "127.0.0.1" | "::1" | "localhost") || h.starts_with("127.")
}

/// Bind `host:port`. Port 0 + range → first free in range; port 0 alone → OS ephemeral.
pub(crate) fn bind_listener(spec: &str, range: Option<(u16, u16)>) -> Result<TcpListener, String> {
    let (host, port) = split_listen_spec(spec)?;
    if port != 0 {
        return TcpListener::bind((host.as_str(), port))
            .map_err(|e| format!("bind {host}:{port}: {e}"));
    }
    if let Some((lo, hi)) = range {
        let mut last = None;
        for p in lo..=hi {
            match TcpListener::bind((host.as_str(), p)) {
                Ok(l) => return Ok(l),
                Err(e) => last = Some(e),
            }
        }
        return Err(format!(
            "no free listen port in {lo}-{hi} on {host}: {}",
            last.map(|e| e.to_string()).unwrap_or_default()
        ));
    }
    TcpListener::bind((host.as_str(), 0u16)).map_err(|e| format!("bind {host}:0: {e}"))
}

pub(crate) fn bind_ephemeral(range: Option<(u16, u16)>) -> Result<TcpListener, String> {
    // BBX_BIND overrides default all-interfaces listen (e.g. 127.0.0.1 or LAN IP).
    let host = env::var("BBX_BIND")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "0.0.0.0".into());
    if host.contains([' ', '"', '\'', ';', '&', '|', '$', '`', '\n', '\r']) {
        return Err(format!("BBX_BIND has illegal characters: {host:?}"));
    }
    bind_listener(&format!("{host}:0"), range)
}

pub(crate) fn split_listen_spec(spec: &str) -> Result<(String, u16), String> {
    let spec = spec.trim();
    if let Some(rest) = spec.strip_prefix('[') {
        // [v6]:port
        let end = rest
            .find(']')
            .ok_or_else(|| format!("bad listen addr {spec:?}"))?;
        let host = rest[..end].to_string();
        let after = &rest[end + 1..];
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| format!("bad listen addr {spec:?}"))?
            .parse()
            .map_err(|_| format!("bad listen port in {spec:?}"))?;
        return Ok((host, port));
    }
    let idx = spec
        .rfind(':')
        .ok_or_else(|| format!("bad listen addr {spec:?}, want host:port"))?;
    let host = spec[..idx].to_string();
    let port: u16 = spec[idx + 1..]
        .parse()
        .map_err(|_| format!("bad listen port in {spec:?}"))?;
    if host.is_empty() {
        return Err(format!("bad listen host in {spec:?}"));
    }
    Ok((host, port))
}

pub(crate) fn host_only(remote: &str) -> &str {
    remote.rsplit('@').next().unwrap_or(remote)
}

/// IP the peer should dial for reverse/pull listen modes.
/// Order: `BBX_ADVERTISE` → route toward remote host → default route UDP → non-loopback iface.
pub(crate) fn advertise_ip(remote: Option<&str>) -> String {
    if let Ok(v) = env::var("BBX_ADVERTISE") {
        let v = v.trim();
        if !v.is_empty() {
            match validate_advertise(v) {
                Ok(()) => return v.to_string(),
                Err(e) => eprintln!("bbx: {e}; ignoring BBX_ADVERTISE"),
            }
        }
    }
    let ip = if let Some(r) = remote {
        guess_ip_toward(host_only(r))
            .or_else(guess_local_ip)
            .or_else(guess_ip_from_proc_route)
            .unwrap_or_else(|| "127.0.0.1".into())
    } else {
        guess_local_ip()
            .or_else(guess_ip_from_proc_route)
            .unwrap_or_else(|| "127.0.0.1".into())
    };
    if remote.is_some() && (ip == "127.0.0.1" || ip == "::1") {
        eprintln!(
            "bbx: warning: advertise IP is loopback ({ip}); remote peer cannot dial this — set BBX_ADVERTISE"
        );
    }
    ip
}

/// Reject shell/control metacharacters and empty advertise values.
pub(crate) fn validate_advertise(v: &str) -> Result<(), String> {
    if v.is_empty() {
        return Err("BBX_ADVERTISE is empty".into());
    }
    if v.chars().any(|c| {
        c.is_control()
            || matches!(c, ' ' | '"' | '\'' | ';' | '&' | '|' | '$' | '`' | '(' | ')' | '<' | '>')
    }) {
        return Err(format!("BBX_ADVERTISE has illegal characters: {v:?}"));
    }
    // Hostname or IP-ish: alnum, dots, colons, hyphens, percent (zone id)
    if !v
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '%'))
    {
        return Err(format!("BBX_ADVERTISE is not a host/IP: {v:?}"));
    }
    Ok(())
}

pub(crate) fn guess_ip_toward(host: &str) -> Option<String> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    // Prefer SSH port; fall back to HTTPS if filtered.
    if s.connect(format!("{host}:22")).is_err() {
        s.connect(format!("{host}:443")).ok()?;
    }
    let ip = s.local_addr().ok()?.ip();
    if ip.is_unspecified() || ip.is_loopback() {
        return None;
    }
    Some(ip.to_string())
}

pub(crate) fn guess_local_ip() -> Option<String> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    let ip = s.local_addr().ok()?.ip();
    if ip.is_loopback() {
        return None;
    }
    Some(ip.to_string())
}

/// First non-loopback IPv4 with a default route from `/proc/net/route` (Linux).
pub(crate) fn guess_ip_from_proc_route() -> Option<String> {
    let data = std::fs::read_to_string("/proc/net/route").ok()?;
    let mut iface = None;
    for line in data.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let ifname = cols.next()?;
        let dest = cols.next()?;
        if dest == "00000000" {
            iface = Some(ifname.to_string());
            break;
        }
    }
    let iface = iface?;
    // /proc/net/fib_trie is heavy; use `ip -4 -o addr` if present, else hostname -I.
    if let Ok(out) = Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", &iface])
        .output()
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            for part in s.split_whitespace() {
                if let Some(cidr) = part.split('/').next() {
                    if cidr.contains('.') && !cidr.starts_with("127.") {
                        return Some(cidr.to_string());
                    }
                }
            }
        }
    }
    None
}

pub(crate) fn io_timeout() -> Duration {
    let secs = env::var("BBX_IO_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(IO_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Wrap a socket error with stream context, and name a timeout for what it is.
/// A read/write timeout surfaces as WouldBlock (EAGAIN) on Unix.
pub(crate) fn io_err(stream_id: u32, op: &str, e: String) -> String {
    if e.contains("temporarily unavailable")
        || e.contains("timed out")
        || e.contains("os error 11")
        || e.contains("os error 110")
    {
        format!("stream {stream_id} {op} timed out after {}s (peer stalled or dead)", io_timeout().as_secs())
    } else {
        format!("stream {stream_id} {op}: {e}")
    }
}

/// Bound `accept()` so a listening side with no dialer doesn't block forever.
/// SO_RCVTIMEO makes accept() return WouldBlock after the timeout on Unix.
#[cfg(unix)]
pub(crate) fn set_accept_timeout(l: &TcpListener) {
    use std::os::unix::io::AsRawFd;
    // musl libc deprecates time_t alias; field is still the socket API type.
    #[allow(deprecated)]
    let tv = libc::timeval {
        tv_sec: io_timeout().as_secs() as libc::time_t,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            l.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const _,
            std::mem::size_of_val(&tv) as libc::socklen_t,
        );
    }
}

#[cfg(not(unix))]
pub(crate) fn set_accept_timeout(_l: &TcpListener) {}

pub(crate) fn accept_err(role: &str, i: usize, e: std::io::Error) -> String {
    use std::io::ErrorKind::{TimedOut, WouldBlock};
    if matches!(e.kind(), WouldBlock | TimedOut) {
        format!(
            "{role} accept[{i}] timed out after {}s (no peer connected)",
            io_timeout().as_secs()
        )
    } else {
        format!("{role} accept[{i}]: {e}")
    }
}

/// Dialer → accepter: u32 LE stream id; with crypt, +16-byte PSK MAC (SID tag).
pub(crate) fn dial_streams(
    addr: &str,
    streams: usize,
    wnd: usize,
    psk: Option<&[u8; 32]>,
) -> Result<Vec<TcpStream>, String> {
    let dest: SocketAddr = addr.parse::<SocketAddr>().map_err(|e| e.to_string())?;
    let mut conns = Vec::with_capacity(streams);
    for i in 0..streams {
        let mut s = TcpStream::connect_timeout(&dest, CONNECT_TIMEOUT)
            .map_err(|e| format!("connect[{i}]: {e}"))?;
        tune(&s, wnd);
        write_u32(&mut s, i as u32).map_err(|e| format!("stream-id write[{i}]: {e}"))?;
        if let Some(k) = psk {
            let tag = stream_id_tag(k, i as u32);
            s.write_all(&tag)
                .map_err(|e| format!("stream-id mac write[{i}]: {e}"))?;
        }
        conns.push(s);
    }
    Ok(conns)
}

/// Optional peer allowlist from `BBX_PEER_ALLOW` (comma-separated IPs). Empty = any peer.
pub(crate) fn peer_allowlist() -> Option<Vec<std::net::IpAddr>> {
    let v = env::var("BBX_PEER_ALLOW").ok()?;
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for part in v.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        match p.parse::<std::net::IpAddr>() {
            Ok(ip) => out.push(ip),
            Err(_) => eprintln!("bbx: warning: BBX_PEER_ALLOW skip bad IP {p:?}"),
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

pub(crate) fn accept_streams(
    listener: &TcpListener,
    streams: usize,
    wnd: usize,
    role: &str,
    psk: Option<&[u8; 32]>,
) -> Result<Vec<TcpStream>, String> {
    set_accept_timeout(listener);
    let allow = peer_allowlist();
    let mut slots: Vec<Option<TcpStream>> = (0..streams).map(|_| None).collect();
    for i in 0..streams {
        let (mut s, peer) = listener
            .accept()
            .map_err(|e| accept_err(role, i, e))?;
        if let Some(ref allow) = allow {
            let ip = peer.ip();
            if !allow.iter().any(|a| *a == ip) {
                return Err(format!(
                    "{role} reject peer {ip} (not in BBX_PEER_ALLOW)"
                ));
            }
        }
        tune(&s, wnd);
        let id = read_u32(&mut s).map_err(|e| format!("{role} stream-id read[{i}]: {e}"))? as usize;
        if id >= streams {
            return Err(format!(
                "{role} bad stream id {id} (expected 0..{})",
                streams.saturating_sub(1)
            ));
        }
        if let Some(k) = psk {
            let mut tag = [0u8; SID_TAG_LEN];
            s.read_exact(&mut tag)
                .map_err(|e| format!("{role} stream-id mac read[{i}]: {e}"))?;
            let expect = stream_id_tag(k, id as u32);
            if tag != expect {
                return Err(format!("{role} bad stream-id MAC for id {id}"));
            }
        }
        if slots[id].is_some() {
            return Err(format!("{role} duplicate stream id {id}"));
        }
        slots[id] = Some(s);
    }
    Ok(slots.into_iter().map(|s| s.expect("filled")).collect())
}

pub(crate) fn tune(s: &TcpStream, wnd: usize) {
    let _ = s.set_nodelay(true);
    let t = io_timeout();
    let _ = s.set_read_timeout(Some(t));
    let _ = s.set_write_timeout(Some(t));
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = s.as_raw_fd();
        let v = wnd as libc::c_int;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &v as *const _ as *const _,
                std::mem::size_of_val(&v) as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &v as *const _ as *const _,
                std::mem::size_of_val(&v) as libc::socklen_t,
            );
        }
    }
    let _ = wnd;
}
