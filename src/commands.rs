//! Subcommand entry points (sink/source/cp) and remote-spec parsing.

use crate::{TREE_SINGLE_STREAM_MAX};
use crate::cli::{TransferOpts, parse_flags};
use crate::cp::{cp_pull_forward, cp_pull_reverse, cp_push_forward, cp_push_reverse};
use crate::crypto::env_key;
use crate::engine::{run_sink_connect, run_sink_listen, run_source_connect, run_source_listen};
use crate::ssh::remote_bin;
use crate::tree::{cp_pull_tree, cp_push_tree};

pub fn cmd_sink(args: &[String]) -> Result<(), String> {
    let f = parse_flags(args)?;
    let out = f.output.ok_or("sink needs -o FILE")?;
    let key = f.key.or_else(env_key);
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
    let input = f.input.ok_or("source needs -i FILE")?;
    let key = f.key.or_else(env_key);
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

/// Cap streams for small files (tree mode stability).
pub(crate) fn streams_for_file(path: &str, streams: usize) -> usize {
    match std::fs::metadata(path).map(|m| m.len()) {
        Ok(n) if n <= TREE_SINGLE_STREAM_MAX && streams > 1 => 1,
        _ => streams,
    }
}
