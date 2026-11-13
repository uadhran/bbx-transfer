//! Subcommand entry points (sink/source/cp) and remote-spec parsing.

use crate::{TREE_SINGLE_STREAM_MAX};
use crate::cli::{parse_flags, parse_key, Flags, TransferOpts};
use crate::cp::{cp_pull_forward, cp_pull_reverse, cp_push_forward, cp_push_reverse};
use crate::crypto::env_key;
use crate::engine::{run_sink_connect, run_sink_listen, run_source_connect, run_source_listen};
use crate::ssh::remote_bin;
use crate::tree::{cp_pull_tree, cp_push_tree};

pub fn cmd_sink(args: &[String]) -> Result<(), String> {
    let f = parse_flags(args)?;
    let key = resolve_agent_key(&f)?;
    let out = f.output.ok_or("sink needs -o FILE")?;
    let crypt = f.crypt || key.is_some();
    match (&f.listen, &f.addr) {
        (Some(l), None) => run_sink_listen(
            l, f.port_range, &out, f.streams, f.wnd, f.check, crypt, key, f.resume, f.json,
            f.progress, f.rate_limit,
        ),
        (None, Some(a)) => run_sink_connect(
            a, &out, f.streams, f.wnd, f.check, f.progress, crypt, key, f.resume, f.json,
            f.rate_limit,
        ),
        _ => Err("sink needs exactly one of -l ADDR or -a ADDR".into()),
    }
}

pub fn cmd_source(args: &[String]) -> Result<(), String> {
    let f = parse_flags(args)?;
    let key = resolve_agent_key(&f)?;
    let input = f.input.ok_or("source needs -i FILE")?;
    let crypt = f.crypt || key.is_some();
    let rf = f.resume_from;
    match (&f.listen, &f.addr) {
        (None, Some(a)) => run_source_connect(
            a, &input, f.streams, f.wnd, f.progress, f.check, crypt, key, rf, f.json,
            f.preserve, f.rate_limit,
        ),
        (Some(l), None) => run_source_listen(
            l, f.port_range, &input, f.streams, f.wnd, f.progress, f.check, crypt, key, rf, f.json,
            f.preserve, f.rate_limit,
        ),
        _ => Err("source needs exactly one of -a ADDR or -l ADDR".into()),
    }
}

pub fn cmd_cp(args: &[String]) -> Result<(), String> {
    let f = parse_flags(args)?;
    if f.key_stdin {
        return Err("--key-stdin is only for sink and source".into());
    }
    if f.rest.len() != 2 {
        return Err("cp needs SRC DEST".into());
    }
    let src = f.rest[0].as_str();
    let dest = f.rest[1].as_str();
    let check = if f.check_set { f.check } else { true };
    let crypt = if f.crypt_set { f.crypt } else { true };
    // Optional fixed session key: -k or BBX_KEY. If set on push-forward, overrides the
    // peer KEY banner (must match remote or decrypt fails closed).
    let fixed_key = f.key.or_else(env_key);
    let bin = remote_bin();
    let rev = f.reverse;
    let recurse = f.recurse;
    let pr = f.port_range;
    let opts = TransferOpts {
        streams: f.streams,
        wnd: f.wnd,
        progress: f.progress,
        check,
        crypt,
        resume: f.resume,
        json: f.json,
        preserve: f.preserve,
        rate: f.rate_limit,
    };

    match (is_remote_spec(src), is_remote_spec(dest)) {
        (false, true) => {
            let (remote, rpath) = split_host_path(dest)?;
            if recurse {
                cp_push_tree(&bin, remote, rpath, src, opts, rev, pr, fixed_key)
            } else if rev {
                cp_push_reverse(&bin, remote, rpath, src, opts, pr, fixed_key)
            } else {
                cp_push_forward(&bin, remote, rpath, src, opts, pr, fixed_key)
            }
        }
        (true, false) => {
            let (remote, rpath) = split_host_path(src)?;
            if recurse {
                cp_pull_tree(&bin, remote, rpath, dest, opts, rev, pr, fixed_key)
            } else if rev {
                cp_pull_reverse(&bin, remote, rpath, dest, opts, pr, fixed_key)
            } else {
                cp_pull_forward(&bin, remote, rpath, dest, opts, pr, fixed_key)
            }
        }
        (false, false) => Err("cp needs one remote host:path side".into()),
        (true, true) => Err("remote→remote not supported".into()),
    }
}

pub fn is_remote_spec(s: &str) -> bool {
    if s.starts_with('/') || s.starts_with("./") || s.starts_with("../") {
        return false;
    }
    // Bracketed IPv6: [addr]:path or user@[addr]:path
    if let Some(br) = s.find("]:") {
        if s[..br].contains('[') {
            return !s[br + 2..].is_empty();
        }
    }
    match s.rfind(':') {
        None => false,
        Some(i) => {
            let host = &s[..i];
            // Avoid treating Windows drive letters as remote (C:/path).
            if host.len() == 1 && host.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
                return false;
            }
            !host.is_empty() && !host.contains('/')
        }
    }
}

pub fn split_host_path(spec: &str) -> Result<(&str, &str), String> {
    // [v6]:path or user@[v6]:path — split on first "]:", not last colon inside address.
    if let Some(br) = spec.find("]:") {
        if spec[..br].contains('[') {
            let host = &spec[..br + 1];
            let path = &spec[br + 2..];
            if host.is_empty() || path.is_empty() {
                return Err("bad host:path".into());
            }
            return Ok((host, path));
        }
    }
    let idx = spec.rfind(':').ok_or("need host:path")?;
    let (host, path) = spec.split_at(idx);
    let path = &path[1..];
    if host.is_empty() || path.is_empty() {
        return Err("bad host:path".into());
    }
    Ok((host, path))
}

fn resolve_agent_key(f: &Flags) -> Result<Option<[u8; 32]>, String> {
    if f.key_stdin {
        if f.key.is_some() {
            return Err("--key-stdin cannot be combined with -k".into());
        }
        return Ok(Some(read_key_stdin()?));
    }
    Ok(f.key.or_else(env_key))
}

/// One 64-hex line, then the agent does not read stdin again. The local side closes the pipe.
fn read_key_stdin() -> Result<[u8; 32], String> {
    use std::io::ErrorKind;
    let fd = libc::STDIN_FILENO;
    let mut buf = [0u8; 65];
    let mut n = 0usize;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while n < buf.len() && !buf[..n].contains(&b'\n') {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err("key-stdin: timed out waiting for the key line".into());
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = left.as_millis().min(i32::MAX as u128) as libc::c_int;
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc == 0 {
            return Err("key-stdin: timed out waiting for the key line".into());
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("key-stdin: {err}"));
        }
        let rc = unsafe {
            libc::read(
                fd,
                buf[n..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - n,
            )
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted || err.kind() == ErrorKind::WouldBlock {
                continue;
            }
            return Err(format!("key-stdin: {err}"));
        }
        if rc == 0 {
            return Err("key-stdin: expected one hex line".into());
        }
        n += rc as usize;
    }
    let end = buf[..n]
        .iter()
        .position(|&b| b == b'\n')
        .ok_or("key-stdin: expected one hex line")?;
    let line = std::str::from_utf8(&buf[..end]).map_err(|_| "key-stdin: expected one hex line")?;
    parse_key(line.trim_end_matches('\r')).map_err(|e| format!("key-stdin: {e}"))
}

/// Cap streams for small files (tree mode stability).
pub(crate) fn streams_for_file(path: &str, streams: usize) -> usize {
    match std::fs::metadata(path).map(|m| m.len()) {
        Ok(n) if n <= TREE_SINGLE_STREAM_MAX && streams > 1 => 1,
        _ => streams,
    }
}
