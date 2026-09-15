//! Per-range payload framing: throttle, encrypted/cleartext send & recv, preserve.

use crate::{CHUNK, CRYPT_PT};
use crate::crypto::{aead_decrypt, aead_encrypt};
use crate::net::io_err;
use crate::util::{read_at_full, read_u32, write_at_full, write_u32};
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
#[cfg(windows)]
use std::os::windows::fs::FileExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// Sleep so cumulative `total` bytes stay near `rate` bytes/sec since `t0`.
pub(crate) fn throttle(rate: u64, total: u64, t0: Instant) {
    if rate == 0 {
        return;
    }
    let elapsed = t0.elapsed().as_secs_f64().max(1e-6);
    let allowed = (rate as f64 * elapsed) as u64;
    if total > allowed {
        let wait = (total - allowed) as f64 / rate as f64;
        if wait > 0.0 {
            thread::sleep(Duration::from_secs_f64(wait.min(2.0)));
        }
    }
}

pub(crate) fn send_range(
    sock: &mut TcpStream,
    f: &File,
    start: u64,
    end: u64,
    stream_id: u32,
    key: Option<&[u8; 32]>,
    aad: Option<&[u8]>,
    sent: &AtomicU64,
    abort: &AtomicBool,
    rate: u64,
    rate_start: Instant,
) -> Result<(), String> {
    let mut off = start;
    let mut left = end - start;
    let mut buf = vec![0u8; if key.is_some() { CRYPT_PT } else { CHUNK }];
    let mut counter = 0u64;
    let aad = aad.unwrap_or(&[]);

    while left > 0 {
        if abort.load(Ordering::Relaxed) {
            return Err(format!("stream {stream_id} aborted (peer stream failed)"));
        }
        let want = left.min(buf.len() as u64) as usize;
        read_at_full(f, &mut buf[..want], off)?;
        if let Some(k) = key {
            let ct = aead_encrypt(k, stream_id, counter, &buf[..want], aad)?;
            counter += 1;
            write_u32(sock, ct.len() as u32).map_err(|e| io_err(stream_id, "write", e))?;
            sock.write_all(&ct).map_err(|e| io_err(stream_id, "write", e.to_string()))?;
        } else {
            sock.write_all(&buf[..want])
                .map_err(|e| io_err(stream_id, "write", e.to_string()))?;
        }
        let n = sent.fetch_add(want as u64, Ordering::Relaxed) + want as u64;
        throttle(rate, n, rate_start);
        off += want as u64;
        left -= want as u64;
    }
    Ok(())
}

pub(crate) fn recv_range(
    sock: &mut TcpStream,
    f: &File,
    start: u64,
    end: u64,
    stream_id: u32,
    key: Option<&[u8; 32]>,
    aad: Option<&[u8]>,
    got: &AtomicU64,
    abort: &AtomicBool,
    rate: u64,
    rate_start: Instant,
) -> Result<(), String> {
    let mut off = start;
    let mut left = end - start;
    let mut buf = vec![0u8; CHUNK];
    let mut counter = 0u64;
    let aad = aad.unwrap_or(&[]);

    while left > 0 {
        if abort.load(Ordering::Relaxed) {
            return Err(format!("stream {stream_id} aborted (peer stream failed)"));
        }
        if let Some(k) = key {
            let clen = read_u32(sock).map_err(|e| io_err(stream_id, "read", e))? as usize;
            if clen > CRYPT_PT + 16 + 64 {
                return Err(format!("bad ciphertext len {clen}"));
            }
            let mut ct = vec![0u8; clen];
            sock.read_exact(&mut ct)
                .map_err(|e| io_err(stream_id, "read", e.to_string()))?;
            let pt = aead_decrypt(k, stream_id, counter, &ct, aad)?;
            counter += 1;
            if pt.len() as u64 > left {
                return Err("decrypt oversize".into());
            }
            write_at_full(f, &pt, off)?;
            let n = got.fetch_add(pt.len() as u64, Ordering::Relaxed) + pt.len() as u64;
            throttle(rate, n, rate_start);
            off += pt.len() as u64;
            left -= pt.len() as u64;
        } else {
            let want = left.min(buf.len() as u64) as usize;
            sock.read_exact(&mut buf[..want])
                .map_err(|e| io_err(stream_id, "read", e.to_string()))?;
            write_at_full(f, &buf[..want], off)?;
            let n = got.fetch_add(want as u64, Ordering::Relaxed) + want as u64;
            throttle(rate, n, rate_start);
            off += want as u64;
            left -= want as u64;
        }
    }
    Ok(())
}

pub(crate) fn file_mode_mtime(meta: &std::fs::Metadata) -> Result<(u32, u64), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode() & 0o7777;
        let mtime = meta.mtime() as u64;
        Ok((mode, mtime))
    }
    #[cfg(not(unix))]
    {
        let mtime = meta
            .modified()
            .map_err(|e| e.to_string())?
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok((0o644, mtime))
    }
}

pub(crate) fn apply_preserve(path: &str, mode: u32, mtime: u64) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms).map_err(|e| e.to_string())?;
        // utimes via libc
        // Infer tv_sec type (avoids deprecated libc::time_t alias on musl).
        let tv = libc::timeval {
            tv_sec: mtime as _,
            tv_usec: 0,
        };
        let times = [tv, tv];
        let c = std::ffi::CString::new(path).map_err(|e| e.to_string())?;
        let rc = unsafe { libc::utimes(c.as_ptr(), times.as_ptr()) };
        if rc != 0 {
            return Err(format!("utimes: {}", std::io::Error::last_os_error()));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode, mtime);
        // mode bits not portable; mtime via filetime would need extra dep — skip mode on non-unix
    }
    Ok(())
}
