//! cp push/pull modes (forward/reverse) and remote file size probes.

use crate::cli::{TransferOpts, z_flag};
use crate::crypto::{gen_key, hex};
use crate::engine::{run_sink_connect, run_sink_with_listener, run_source_connect, run_source_with_listener};
use crate::net::{advertise_ip, bind_ephemeral, host_only};
use crate::ssh::{ce_flags, finish_agent, resume_flag, shell_quote, ssh_spawn, ssh_start_banner};
use std::process::{Command, Stdio};

pub(crate) fn preserve_flag(preserve: bool) -> &'static str {
    if preserve {
        " --preserve"
    } else {
        ""
    }
}

pub(crate) fn rate_flag(rate: u64) -> String {
    if rate > 0 {
        format!(" -x {rate}")
    } else {
        String::new()
    }
}

pub(crate) fn cp_push_forward(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_src: &str,
    opts: TransferOpts,
    port_range: Option<(u16, u16)>,
    fixed_key: Option<[u8; 32]>,
) -> Result<(), String> {
    let ce = ce_flags(opts.check, opts.crypt);
    let z = z_flag(port_range);
    let pf = preserve_flag(opts.preserve);
    let xf = rate_flag(opts.rate);
    let streams = opts.streams;
    let wnd = opts.wnd;
    // Remote generates KEY (banner). Local uses banner unless -k/BBX_KEY overrides.
    let cmd = format!(
        "{} sink -l 0.0.0.0:0{z} -o {} -s {streams} -w {wnd} {ce}{}{pf}{xf}",
        shell_quote(bin),
        shell_quote(rpath),
        resume_flag(opts.resume)
    );
    let (mut child, port, banner_key, resume_from) =
        ssh_start_banner(remote, &cmd, opts.crypt, opts.resume)?;
    let key = if opts.crypt {
        Some(fixed_key.or(banner_key).ok_or("encrypt: no session key from peer")?)
    } else {
        None
    };
    let host = host_only(remote);
    let addr = format!("{host}:{port}");
    if !opts.json {
        eprintln!(
            "bbx: push {local_src} → {remote}:{rpath} via {addr} streams={streams} resume_from={resume_from} crypt={}",
            opts.crypt
        );
    }
    let r = run_source_connect(
        &addr,
        local_src,
        opts.streams,
        opts.wnd,
        opts.progress,
        opts.check,
        opts.crypt,
        key,
        resume_from,
        opts.json,
        opts.preserve,
        opts.rate,
    );
    finish_agent(&mut child, r, "push remote sink")
}

pub(crate) fn cp_push_reverse(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_src: &str,
    opts: TransferOpts,
    port_range: Option<(u16, u16)>,
    fixed_key: Option<[u8; 32]>,
) -> Result<(), String> {
    let resume_from = if opts.resume {
        remote_file_len(remote, rpath)?
    } else {
        0
    };
    let listener = bind_ephemeral(port_range)?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let advertise = advertise_ip(Some(remote));
    let addr = format!("{advertise}:{port}");
    let key = if opts.crypt {
        Some(fixed_key.unwrap_or_else(gen_key))
    } else {
        None
    };
    let ce = ce_flags(opts.check, opts.crypt);
    let pf = preserve_flag(opts.preserve);
    let xf = rate_flag(opts.rate);
    let streams = opts.streams;
    let wnd = opts.wnd;
    let kenv = key
        .as_ref()
        .map(|k| format!("BBX_KEY={} ", hex(k)))
        .unwrap_or_default();
    let cmd = format!(
        "{kenv}{} sink -a {} -o {} -s {streams} -w {wnd} {ce}{}{pf}{xf}",
        shell_quote(bin),
        shell_quote(&addr),
        shell_quote(rpath),
        resume_flag(opts.resume)
    );
    if !opts.json {
        eprintln!(
            "bbx: push -z {local_src} → {remote}:{rpath} dials {addr} resume_from={resume_from}"
        );
    }
    let mut child = ssh_spawn(remote, &cmd)?;
    let r = run_source_with_listener(
        listener,
        local_src,
        opts.streams,
        opts.wnd,
        opts.progress,
        opts.check,
        opts.crypt,
        key,
        resume_from,
        opts.json,
        opts.preserve,
        opts.rate,
    );
    finish_agent(&mut child, r, "push -z remote sink")
}

pub(crate) fn cp_pull_forward(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_dst: &str,
    opts: TransferOpts,
    port_range: Option<(u16, u16)>,
    fixed_key: Option<[u8; 32]>,
) -> Result<(), String> {
    let listener = bind_ephemeral(port_range)?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let advertise = advertise_ip(Some(remote));
    let addr = format!("{advertise}:{port}");
    let key = if opts.crypt {
        Some(fixed_key.unwrap_or_else(gen_key))
    } else {
        None
    };
    let ce = ce_flags(opts.check, opts.crypt);
    let pf = preserve_flag(opts.preserve);
    let xf = rate_flag(opts.rate);
    let streams = opts.streams;
    let wnd = opts.wnd;
    let kenv = key
        .as_ref()
        .map(|k| format!("BBX_KEY={} ", hex(k)))
        .unwrap_or_default();
    let rf = if opts.resume {
        std::fs::metadata(local_dst).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    let rarg = if opts.resume && rf > 0 {
        format!(" -R {rf}")
    } else {
        String::new()
    };
    let cmd = format!(
        "{kenv}{} source -a {} -i {} -s {streams} -w {wnd} {ce}{rarg}{pf}{xf}",
        shell_quote(bin),
        shell_quote(&addr),
        shell_quote(rpath)
    );
    if !opts.json {
        eprintln!("bbx: pull {remote}:{rpath} → {local_dst} listen={addr} resume_from={rf}");
    }
    let mut child = ssh_spawn(remote, &cmd)?;
    let r = run_sink_with_listener(
        listener,
        local_dst,
        opts.streams,
        opts.wnd,
        opts.check,
        opts.progress,
        opts.crypt,
        key,
        opts.resume,
        opts.json,
        opts.rate,
    );
    finish_agent(&mut child, r, "pull remote source")
}

pub(crate) fn cp_pull_reverse(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_dst: &str,
    opts: TransferOpts,
    port_range: Option<(u16, u16)>,
    fixed_key: Option<[u8; 32]>,
) -> Result<(), String> {
    let ce = ce_flags(opts.check, opts.crypt);
    let z = z_flag(port_range);
    let pf = preserve_flag(opts.preserve);
    let xf = rate_flag(opts.rate);
    let streams = opts.streams;
    let wnd = opts.wnd;
    let rf = if opts.resume {
        std::fs::metadata(local_dst).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    let rarg = if opts.resume && rf > 0 {
        format!(" -R {rf}")
    } else {
        String::new()
    };
    let kenv = fixed_key
        .as_ref()
        .filter(|_| opts.crypt)
        .map(|k| format!("BBX_KEY={} ", hex(k)))
        .unwrap_or_default();
    let cmd = format!(
        "{kenv}{} source -l 0.0.0.0:0{z} -i {} -s {streams} -w {wnd} {ce}{rarg}{pf}{xf}",
        shell_quote(bin),
        shell_quote(rpath)
    );
    let (mut child, port, banner_key, _) = ssh_start_banner(remote, &cmd, opts.crypt, false)?;
    let key = if opts.crypt {
        Some(fixed_key.or(banner_key).ok_or("encrypt: no session key from peer")?)
    } else {
        None
    };
    let host = host_only(remote);
    let addr = format!("{host}:{port}");
    if !opts.json {
        eprintln!("bbx: pull -z {remote}:{rpath} → {local_dst} via {addr} resume_from={rf}");
    }
    let r = run_sink_connect(
        &addr,
        local_dst,
        opts.streams,
        opts.wnd,
        opts.check,
        opts.progress,
        opts.crypt,
        key,
        opts.resume,
        opts.json,
        opts.rate,
    );
    finish_agent(&mut child, r, "pull -z remote source")
}

pub(crate) fn remote_file_len(remote: &str, path: &str) -> Result<u64, String> {
    let out = Command::new("ssh")
        .arg(remote)
        .arg(format!(
            "stat -c %s {} 2>/dev/null || echo 0",
            shell_quote(path)
        ))
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("ssh stat: {e}"))?;
    let s = String::from_utf8_lossy(&out.stdout);
    s.trim()
        .lines()
        .last()
        .unwrap_or("0")
        .parse()
        .map_err(|_| format!("bad remote size: {s:?}"))
}
