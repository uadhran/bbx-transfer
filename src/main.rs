//! bbx — multi-stream bulk copy (BBX2).
//!
//! sink/source/cp with: -s -w -P -c|-C -e|-E -k -A (resume) -J (json) -z
//! See SPEC.md.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const MAGIC: &[u8; 4] = b"BBX2";
const DEFAULT_STREAMS: usize = 4;
const DEFAULT_WND: usize = 4 * 1024 * 1024;
const CHUNK: usize = 1024 * 1024;
const CRYPT_PT: usize = 64 * 1024;
const FLAG_BLAKE3: u32 = 1;
const FLAG_CRYPT: u32 = 2;
const FLAG_RESUME: u32 = 4;
const FLAG_PRESERVE: u32 = 8;
/// Tree mode: files smaller than this use a single stream (cuts multi-stream races on tiny files).
const TREE_SINGLE_STREAM_MAX: u64 = 1024 * 1024;
/// Reserved AEAD counter for sealed control meta (payload counters start at 0).
const CONTROL_COUNTER: u64 = u64::MAX;
/// Stream-id MAC tag length (BLAKE3 keyed truncate).
const SID_TAG_LEN: usize = 16;

// A stalled-but-open peer must not hang the transfer forever. Data sockets get
// a read/write timeout (overridable via BBX_IO_TIMEOUT_SECS for tests), and
// connection establishment is bounded separately.
const IO_TIMEOUT_SECS: u64 = 120;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage(1);
    }
    let cmd = args.remove(0);
    let rc = match cmd.as_str() {
        "sink" => cmd_sink(&args),
        "source" => cmd_source(&args),
        "cp" => cmd_cp(&args),
        "-h" | "--help" | "help" => {
            usage(0);
            Ok(())
        }
        _ => {
            eprintln!("unknown command: {cmd}");
            usage(1);
            Ok(())
        }
    };
    if let Err(e) = rc {
        eprintln!("bbx: {e}");
        std::process::exit(1);
    }
}

fn usage(code: i32) {
    eprintln!(
        "bbx — multi-stream bulk copy (BBX2)\n\n\
         bbx sink|source|cp …\n\
         opts: -s N -w SIZE -P SEC -c|-C -e|-E -k HEX\n\
               -A resume  -J json  -r recurse dirs  -R BYTES\n\
               -z reverse  -Z LO-HI  listen port range (firewall)\n\
               --preserve mode+mtime  -x RATE  throttle bytes/sec\n\
         cp defaults: -c -e on. -A resumes partial dest.\n\
         BBX_REMOTE=  BBX_ADVERTISE=  BBX_KEY=  BBX_PORT_RANGE=  BBX_IO_TIMEOUT_SECS=\n\
         BBX_BIND=  BBX_PEER_ALLOW=  BBX_AGENT_WAIT_SECS=  BBX_ALLOW_CLEAR=1\n"
    );
    std::process::exit(code);
}

/// Cleartext (-E) is loopback-only unless `BBX_ALLOW_CLEAR=1`.
fn cleartext_allowed(hostish: &str) -> Result<(), String> {
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

fn host_is_loopback(s: &str) -> bool {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return sa.ip().is_loopback();
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    let h = s.trim_matches(|c| c == '[' || c == ']');
    matches!(h, "127.0.0.1" | "::1" | "localhost") || h.starts_with("127.")
}

// --- flags -----------------------------------------------------------------

#[derive(Clone)]
struct Flags {
    listen: Option<String>,
    addr: Option<String>,
    input: Option<String>,
    output: Option<String>,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    check_set: bool,
    crypt: bool,
    crypt_set: bool,
    key: Option<[u8; 32]>,
    reverse: bool,
    resume: bool,
    resume_from: u64,
    json: bool,
    recurse: bool,
    /// Inclusive listen port range for firewall-friendly binds (`-Z` / `BBX_PORT_RANGE`).
    port_range: Option<(u16, u16)>,
    /// Preserve mode + mtime (FLAG_PRESERVE on wire).
    preserve: bool,
    /// Max payload bytes/sec (0 = unlimited).
    rate_limit: u64,
    rest: Vec<String>,
}

fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut f = Flags {
        listen: None,
        addr: None,
        input: None,
        output: None,
        streams: DEFAULT_STREAMS,
        wnd: DEFAULT_WND,
        progress: 0,
        check: false,
        check_set: false,
        crypt: false,
        crypt_set: false,
        key: None,
        reverse: false,
        resume: false,
        resume_from: 0,
        json: false,
        recurse: false,
        port_range: None,
        preserve: false,
        rate_limit: 0,
        rest: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-l" => {
                i += 1;
                f.listen = Some(need(args, i, "-l")?.to_string());
            }
            "-a" => {
                i += 1;
                f.addr = Some(need(args, i, "-a")?.to_string());
            }
            "-i" => {
                i += 1;
                f.input = Some(need(args, i, "-i")?.to_string());
            }
            "-o" => {
                i += 1;
                f.output = Some(need(args, i, "-o")?.to_string());
            }
            "-s" => {
                i += 1;
                f.streams = need(args, i, "-s")?
                    .parse()
                    .map_err(|_| "bad -s".to_string())?;
                if f.streams == 0 || f.streams > 64 {
                    return Err("-s must be 1..64".into());
                }
            }
            "-w" => {
                i += 1;
                f.wnd = parse_size(need(args, i, "-w")?)?;
            }
            "-P" => {
                i += 1;
                f.progress = need(args, i, "-P")?
                    .parse()
                    .map_err(|_| "bad -P".to_string())?;
            }
            "-c" => {
                f.check = true;
                f.check_set = true;
            }
            "-C" => {
                f.check = false;
                f.check_set = true;
            }
            "-e" => {
                f.crypt = true;
                f.crypt_set = true;
            }
            "-E" => {
                f.crypt = false;
                f.crypt_set = true;
            }
            "-k" => {
                i += 1;
                f.key = Some(parse_key(need(args, i, "-k")?)?);
            }
            "-z" => f.reverse = true,
            "-A" => f.resume = true,
            "-J" => f.json = true,
            "-r" => f.recurse = true,
            "-R" => {
                i += 1;
                f.resume_from = need(args, i, "-R")?
                    .parse()
                    .map_err(|_| "bad -R".to_string())?;
                f.resume = true;
            }
            "-Z" => {
                i += 1;
                f.port_range = Some(parse_port_range(need(args, i, "-Z")?)?);
            }
            "--preserve" | "-p" => f.preserve = true,
            "-x" => {
                i += 1;
                f.rate_limit = parse_size(need(args, i, "-x")?)? as u64;
                if f.rate_limit == 0 {
                    return Err("-x rate must be > 0".into());
                }
            }
            "--" => {
                f.rest.extend_from_slice(&args[i + 1..]);
                break;
            }
            s if s.starts_with('-') => return Err(format!("unknown flag {s}")),
            s => f.rest.push(s.to_string()),
        }
        i += 1;
    }
    if f.port_range.is_none() {
        if let Ok(s) = env::var("BBX_PORT_RANGE") {
            if !s.trim().is_empty() {
                f.port_range = Some(parse_port_range(&s)?);
            }
        }
    }
    Ok(f)
}

/// `LO-HI` or `LO:HI` inclusive. LO must be ≥1.
fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
    let s = s.trim();
    let (a, b) = s
        .split_once('-')
        .or_else(|| s.split_once(':'))
        .ok_or_else(|| format!("bad port range {s:?}, want LO-HI"))?;
    let lo: u16 = a
        .trim()
        .parse()
        .map_err(|_| format!("bad port range low in {s:?}"))?;
    let hi: u16 = b
        .trim()
        .parse()
        .map_err(|_| format!("bad port range high in {s:?}"))?;
    if lo == 0 {
        return Err("port range LO must be ≥ 1".into());
    }
    if hi < lo {
        return Err(format!("port range HI {hi} < LO {lo}"));
    }
    Ok((lo, hi))
}

fn z_flag(range: Option<(u16, u16)>) -> String {
    match range {
        Some((lo, hi)) => format!(" -Z {lo}-{hi}"),
        None => String::new(),
    }
}

/// Bind `host:port`. Port 0 + range → first free in range; port 0 alone → OS ephemeral.
fn bind_listener(spec: &str, range: Option<(u16, u16)>) -> Result<TcpListener, String> {
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

fn bind_ephemeral(range: Option<(u16, u16)>) -> Result<TcpListener, String> {
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

fn split_listen_spec(spec: &str) -> Result<(String, u16), String> {
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

fn need<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str, String> {
    args.get(i)
        .map(|s| s.as_str())
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn parse_size(s: &str) -> Result<usize, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".into());
    }
    let (num, mul) = match s.as_bytes().last().map(|c| c.to_ascii_uppercase()) {
        Some(b'K') => (&s[..s.len() - 1], 1024usize),
        Some(b'M') => (&s[..s.len() - 1], 1024 * 1024),
        Some(b'G') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    let n: usize = num.parse().map_err(|_| format!("bad size {s}"))?;
    Ok(n.saturating_mul(mul))
}

fn parse_key(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err("key must be 64 hex chars (32 bytes)".into());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| "bad key hex".to_string())?;
    }
    Ok(out)
}

fn gen_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).expect("getrandom");
    k
}

/// Derive a one-time AEAD key from OOB PSK + per-transfer salt.
/// Prevents ChaCha20-Poly1305 nonce reuse when the same `-k`/`BBX_KEY` is reused.
fn derive_aead_key(psk: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(psk, salt).as_bytes()
}

/// MAC over stream id under OOB PSK (before salt). Prevents unauthenticated accept reordering.
fn stream_id_tag(psk: &[u8; 32], id: u32) -> [u8; SID_TAG_LEN] {
    let mut msg = [0u8; 8];
    msg[0..4].copy_from_slice(b"SID\0");
    msg[4..8].copy_from_slice(&id.to_le_bytes());
    let h = blake3::keyed_hash(psk, &msg);
    let mut tag = [0u8; SID_TAG_LEN];
    tag.copy_from_slice(&h.as_bytes()[..SID_TAG_LEN]);
    tag
}

/// AAD bound into every payload AEAD tag when encrypting.
fn frame_aad(flags: u32, size: u64, streams: u32, resume_from: u64, salt: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 8 + 4 + 8 + 32);
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(&streams.to_le_bytes());
    v.extend_from_slice(&resume_from.to_le_bytes());
    v.extend_from_slice(salt);
    v
}

fn aead_encrypt(
    key: &[u8; 32],
    stream_id: u32,
    counter: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let c = ChaCha20Poly1305::new_from_slice(key).map_err(|_| "bad key".to_string())?;
    c.encrypt(
        &make_nonce(stream_id, counter),
        Payload {
            msg: plaintext,
            aad,
        },
    )
    .map_err(|_| "encrypt failed".to_string())
}

fn aead_decrypt(
    key: &[u8; 32],
    stream_id: u32,
    counter: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let c = ChaCha20Poly1305::new_from_slice(key).map_err(|_| "bad key".to_string())?;
    c.decrypt(
        &make_nonce(stream_id, counter),
        Payload {
            msg: ciphertext,
            aad,
        },
    )
    .map_err(|_| "decrypt failed (wrong key or corrupt)".to_string())
}

/// Session key from the `BBX_KEY` environment variable, if present and valid.
/// Preferred over `-k` on the remote side: env is not shown by a plain `ps`.
fn env_key() -> Option<[u8; 32]> {
    let s = env::var("BBX_KEY").ok()?;
    parse_key(&s).ok()
}

/// Quote a path/arg for remote `sh` via ssh.
/// Leading `~/` becomes `"$HOME/..."` so tilde expands (single-quoted `~` does not).
fn shell_quote(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/") {
        format!("\"$HOME/{}\"", shell_escape_dq(rest))
    } else if s == "~" {
        "\"$HOME\"".into()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

fn shell_escape_dq(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
}

fn remote_bin() -> String {
    env::var("BBX_REMOTE").unwrap_or_else(|_| "bbx".into())
}

fn ce_flags(check: bool, crypt: bool) -> String {
    format!(
        "{} {}",
        if check { "-c" } else { "-C" },
        if crypt { "-e" } else { "-E" }
    )
}

fn resume_flag(resume: bool) -> &'static str {
    if resume { " -A" } else { "" }
}


// --- commands --------------------------------------------------------------

fn cmd_sink(args: &[String]) -> Result<(), String> {
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

fn cmd_source(args: &[String]) -> Result<(), String> {
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

fn cmd_cp(args: &[String]) -> Result<(), String> {
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
    let s = f.streams;
    let w = f.wnd;
    let p = f.progress;
    let rev = f.reverse;
    let resume = f.resume;
    let json = f.json;
    let recurse = f.recurse;
    let pr = f.port_range;
    let preserve = f.preserve;
    let rate = f.rate_limit;

    match (is_remote_spec(src), is_remote_spec(dest)) {
        (false, true) => {
            let (remote, rpath) = split_host_path(dest)?;
            if recurse {
                cp_push_tree(
                    &bin, remote, rpath, src, s, w, p, check, crypt, resume, json, rev, pr,
                    fixed_key, preserve, rate,
                )
            } else if rev {
                cp_push_reverse(
                    &bin, remote, rpath, src, s, w, p, check, crypt, resume, json, pr, fixed_key,
                    preserve, rate,
                )
            } else {
                cp_push_forward(
                    &bin, remote, rpath, src, s, w, p, check, crypt, resume, json, pr, fixed_key,
                    preserve, rate,
                )
            }
        }
        (true, false) => {
            let (remote, rpath) = split_host_path(src)?;
            if recurse {
                cp_pull_tree(
                    &bin, remote, rpath, dest, s, w, p, check, crypt, resume, json, rev, pr,
                    fixed_key, preserve, rate,
                )
            } else if rev {
                cp_pull_reverse(
                    &bin, remote, rpath, dest, s, w, p, check, crypt, resume, json, pr, fixed_key,
                    preserve, rate,
                )
            } else {
                cp_pull_forward(
                    &bin, remote, rpath, dest, s, w, p, check, crypt, resume, json, pr, fixed_key,
                    preserve, rate,
                )
            }
        }
        (false, false) => Err("cp needs one remote host:path side".into()),
        (true, true) => Err("remote→remote not supported".into()),
    }
}

fn is_remote_spec(s: &str) -> bool {
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

fn split_host_path(spec: &str) -> Result<(&str, &str), String> {
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
fn streams_for_file(path: &str, streams: usize) -> usize {
    match std::fs::metadata(path).map(|m| m.len()) {
        Ok(n) if n <= TREE_SINGLE_STREAM_MAX && streams > 1 => 1,
        _ => streams,
    }
}


// --- tree walk (P3 -r) -----------------------------------------------------

fn walk_local_files(root: &std::path::Path) -> Result<Vec<(std::path::PathBuf, String)>, String> {
    let root = root
        .canonicalize()
        .map_err(|e| format!("src: {e}"))?;
    if !root.is_dir() {
        return Err(" -r needs a source directory".into());
    }
    let mut out = Vec::new();
    walk_local_rec(&root, &root, &mut out)?;
    out.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(out)
}

fn walk_local_rec(
    base: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<(std::path::PathBuf, String)>,
) -> Result<(), String> {
    for ent in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let ent = ent.map_err(|e| e.to_string())?;
        let path = ent.path();
        let ft = ent.file_type().map_err(|e| e.to_string())?;
        if ft.is_dir() {
            walk_local_rec(base, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(base)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            out.push((path, rel));
        }
        // skip symlinks for now
    }
    Ok(())
}

fn remote_list_files(remote: &str, rpath: &str) -> Result<Vec<String>, String> {
    // relative paths under rpath
    let out = Command::new("ssh")
        .arg(remote)
        .arg(format!(
            "cd {} && find . -type f | sed 's|^\\./||'",
            shell_quote(rpath)
        ))
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("ssh find: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "remote find failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let mut files: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    files.sort();
    Ok(files)
}

/// One SSH round-trip for many parents (tree push).
fn ssh_mkdir_p_many<'a>(
    remote: &str,
    dirs: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    let mut q = String::from("mkdir -p");
    let mut n = 0usize;
    for d in dirs {
        if d.is_empty() {
            continue;
        }
        q.push(' ');
        q.push_str(&shell_quote(d));
        n += 1;
    }
    if n == 0 {
        return Ok(());
    }
    let st = Command::new("ssh")
        .arg(remote)
        .arg(q)
        .stdin(Stdio::inherit())
        .status()
        .map_err(|e| format!("ssh mkdir: {e}"))?;
    if !st.success() {
        return Err("mkdir -p failed".into());
    }
    Ok(())
}

fn join_remote(base: &str, rel: &str) -> String {
    let base = base.trim_end_matches('/');
    if rel.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{rel}")
    }
}

fn parent_posix(path: &str) -> Option<String> {
    let path = path.trim_end_matches('/');
    path.rfind('/').map(|i| path[..i].to_string())
}

/// A relative path from a remote `find` is untrusted: reject anything that is
/// absolute or contains a `..` component so a compromised remote can't make us
/// write outside the local destination directory (path traversal).
fn is_safe_rel(rel: &str) -> bool {
    use std::path::Component;
    if rel.is_empty() {
        return false;
    }
    let p = std::path::Path::new(rel);
    if p.is_absolute() {
        return false;
    }
    p.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// Sequential multi-file push (one BBX2 session per file). Clear, correct, not fancy.
fn cp_push_tree(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_src: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    resume: bool,
    json: bool,
    rev: bool,
    port_range: Option<(u16, u16)>,
    fixed_key: Option<[u8; 32]>,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    let root = std::path::Path::new(local_src);
    let files = walk_local_files(root)?;
    if files.is_empty() {
        return Err("no files under source directory".into());
    }
    // Batch mkdir parents in one SSH (avoid per-file SSH storms).
    let mut parents: Vec<String> = Vec::new();
    parents.push(rpath.trim_end_matches('/').to_string());
    for (_, rel) in &files {
        let remote_file = join_remote(rpath, rel);
        if let Some(parent) = parent_posix(&remote_file) {
            if !parents.iter().any(|p| p == &parent) {
                parents.push(parent);
            }
        }
    }
    ssh_mkdir_p_many(remote, parents.iter().map(|s| s.as_str()))?;
    if !json {
        eprintln!("bbx: push -r {} files → {}:{rpath}", files.len(), remote);
    }
    for (i, (local, rel)) in files.iter().enumerate() {
        let remote_file = join_remote(rpath, rel);
        if !json {
            eprintln!("bbx: [{}/{}] {}", i + 1, files.len(), rel);
        } else {
            println!(
                r#"{{"event":"file","index":{},"total":{},"path":{:?}}}"#,
                i + 1,
                files.len(),
                rel
            );
        }
        let local_s = local.to_string_lossy();
        let s = streams_for_file(&local_s, streams);
        if rev {
            cp_push_reverse(
                bin, remote, &remote_file, &local_s, s, wnd, progress, check, crypt, resume,
                json, port_range, fixed_key, preserve, rate,
            )?;
        } else {
            cp_push_forward(
                bin, remote, &remote_file, &local_s, s, wnd, progress, check, crypt, resume,
                json, port_range, fixed_key, preserve, rate,
            )?;
        }
    }
    if json {
        println!(
            r#"{{"event":"tree_done","files":{},"direction":"push"}}"#,
            files.len()
        );
    } else {
        eprintln!("bbx: tree push done ({} files)", files.len());
    }
    Ok(())
}

fn cp_pull_tree(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_dst: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    resume: bool,
    json: bool,
    rev: bool,
    port_range: Option<(u16, u16)>,
    fixed_key: Option<[u8; 32]>,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    let files = remote_list_files(remote, rpath)?;
    if files.is_empty() {
        return Err("no remote files found (need GNU find -printf or plain find)".into());
    }
    std::fs::create_dir_all(local_dst).map_err(|e| e.to_string())?;
    if !json {
        eprintln!("bbx: pull -r {} files from {}:{rpath}", files.len(), remote);
    }
    for (i, rel) in files.iter().enumerate() {
        if !is_safe_rel(rel) {
            return Err(format!("unsafe remote path rejected: {rel}"));
        }
        let remote_file = join_remote(rpath, rel);
        let local_file = std::path::Path::new(local_dst).join(rel);
        if let Some(parent) = local_file.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if !json {
            eprintln!("bbx: [{}/{}] {}", i + 1, files.len(), rel);
        } else {
            println!(
                r#"{{"event":"file","index":{},"total":{},"path":{:?}}}"#,
                i + 1,
                files.len(),
                rel
            );
        }
        let local_s = local_file.to_string_lossy();
        // Pull: remote size unknown cheaply; use single stream for tree stability.
        let s = if streams > 1 { 1 } else { streams };
        if rev {
            cp_pull_reverse(
                bin, remote, &remote_file, &local_s, s, wnd, progress, check, crypt, resume,
                json, port_range, fixed_key, preserve, rate,
            )?;
        } else {
            cp_pull_forward(
                bin, remote, &remote_file, &local_s, s, wnd, progress, check, crypt, resume,
                json, port_range, fixed_key, preserve, rate,
            )?;
        }
    }
    if json {
        println!(
            r#"{{"event":"tree_done","files":{},"direction":"pull"}}"#,
            files.len()
        );
    } else {
        eprintln!("bbx: tree pull done ({} files)", files.len());
    }
    Ok(())
}

// --- cp modes --------------------------------------------------------------

fn preserve_flag(preserve: bool) -> &'static str {
    if preserve {
        " --preserve"
    } else {
        ""
    }
}

fn rate_flag(rate: u64) -> String {
    if rate > 0 {
        format!(" -x {rate}")
    } else {
        String::new()
    }
}

fn cp_push_forward(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_src: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    resume: bool,
    json: bool,
    port_range: Option<(u16, u16)>,
    fixed_key: Option<[u8; 32]>,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    let ce = ce_flags(check, crypt);
    let z = z_flag(port_range);
    let pf = preserve_flag(preserve);
    let xf = rate_flag(rate);
    // Remote generates KEY (banner). Local uses banner unless -k/BBX_KEY overrides.
    // Override ≠ banner → decrypt fails closed (wrong key).
    let cmd = format!(
        "{} sink -l 0.0.0.0:0{z} -o {} -s {streams} -w {wnd} {ce}{}{pf}{xf}",
        shell_quote(bin),
        shell_quote(rpath),
        resume_flag(resume)
    );
    let (mut child, port, banner_key, resume_from) = ssh_start_banner(remote, &cmd, crypt, resume)?;
    let key = if crypt {
        Some(fixed_key.or(banner_key).ok_or("encrypt: no session key from peer")?)
    } else {
        None
    };
    let host = host_only(remote);
    let addr = format!("{host}:{port}");
    if !json {
        eprintln!(
            "bbx: push {local_src} → {remote}:{rpath} via {addr} streams={streams} resume_from={resume_from} crypt={crypt}"
        );
    }
    let r = run_source_connect(
        &addr, local_src, streams, wnd, progress, check, crypt, key, resume_from, json, preserve,
        rate,
    );
    finish_agent(&mut child, r, "push remote sink")
}

fn cp_push_reverse(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_src: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    resume: bool,
    json: bool,
    port_range: Option<(u16, u16)>,
    fixed_key: Option<[u8; 32]>,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    let resume_from = if resume {
        remote_file_len(remote, rpath)?
    } else {
        0
    };
    let listener = bind_ephemeral(port_range)?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let advertise = advertise_ip(Some(remote));
    let addr = format!("{advertise}:{port}");
    let key = if crypt {
        Some(fixed_key.unwrap_or_else(gen_key))
    } else {
        None
    };
    let ce = ce_flags(check, crypt);
    let pf = preserve_flag(preserve);
    let xf = rate_flag(rate);
    let kenv = key
        .as_ref()
        .map(|k| format!("BBX_KEY={} ", hex(k)))
        .unwrap_or_default();
    let cmd = format!(
        "{kenv}{} sink -a {} -o {} -s {streams} -w {wnd} {ce}{}{pf}{xf}",
        shell_quote(bin),
        shell_quote(&addr),
        shell_quote(rpath),
        resume_flag(resume)
    );
    if !json {
        eprintln!(
            "bbx: push -z {local_src} → {remote}:{rpath} dials {addr} resume_from={resume_from}"
        );
    }
    let mut child = ssh_spawn(remote, &cmd)?;
    let r = run_source_with_listener(
        listener, local_src, streams, wnd, progress, check, crypt, key, resume_from, json,
        preserve, rate,
    );
    finish_agent(&mut child, r, "push -z remote sink")
}

fn cp_pull_forward(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_dst: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    resume: bool,
    json: bool,
    port_range: Option<(u16, u16)>,
    fixed_key: Option<[u8; 32]>,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    let listener = bind_ephemeral(port_range)?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let advertise = advertise_ip(Some(remote));
    let addr = format!("{advertise}:{port}");
    let key = if crypt {
        Some(fixed_key.unwrap_or_else(gen_key))
    } else {
        None
    };
    let ce = ce_flags(check, crypt);
    let pf = preserve_flag(preserve);
    let xf = rate_flag(rate);
    let kenv = key
        .as_ref()
        .map(|k| format!("BBX_KEY={} ", hex(k)))
        .unwrap_or_default();
    let rf = if resume {
        std::fs::metadata(local_dst).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    let rarg = if resume && rf > 0 {
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
    if !json {
        eprintln!("bbx: pull {remote}:{rpath} → {local_dst} listen={addr} resume_from={rf}");
    }
    let mut child = ssh_spawn(remote, &cmd)?;
    let r = run_sink_with_listener(
        listener, local_dst, streams, wnd, check, progress, crypt, key, resume, json, rate,
    );
    finish_agent(&mut child, r, "pull remote source")
}

fn cp_pull_reverse(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_dst: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    resume: bool,
    json: bool,
    port_range: Option<(u16, u16)>,
    fixed_key: Option<[u8; 32]>,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    let ce = ce_flags(check, crypt);
    let z = z_flag(port_range);
    let pf = preserve_flag(preserve);
    let xf = rate_flag(rate);
    let rf = if resume {
        std::fs::metadata(local_dst).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    let rarg = if resume && rf > 0 {
        format!(" -R {rf}")
    } else {
        String::new()
    };
    let kenv = fixed_key
        .as_ref()
        .filter(|_| crypt)
        .map(|k| format!("BBX_KEY={} ", hex(k)))
        .unwrap_or_default();
    let cmd = format!(
        "{kenv}{} source -l 0.0.0.0:0{z} -i {} -s {streams} -w {wnd} {ce}{rarg}{pf}{xf}",
        shell_quote(bin),
        shell_quote(rpath)
    );
    let (mut child, port, banner_key, _) = ssh_start_banner(remote, &cmd, crypt, false)?;
    let key = if crypt {
        Some(fixed_key.or(banner_key).ok_or("encrypt: no session key from peer")?)
    } else {
        None
    };
    let host = host_only(remote);
    let addr = format!("{host}:{port}");
    if !json {
        eprintln!("bbx: pull -z {remote}:{rpath} → {local_dst} via {addr} resume_from={rf}");
    }
    let r = run_sink_connect(
        &addr, local_dst, streams, wnd, check, progress, crypt, key, resume, json, rate,
    );
    finish_agent(&mut child, r, "pull -z remote source")
}

fn remote_file_len(remote: &str, path: &str) -> Result<u64, String> {
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

fn host_only(remote: &str) -> &str {
    remote.rsplit('@').next().unwrap_or(remote)
}

/// IP the peer should dial for reverse/pull listen modes.
/// Order: `BBX_ADVERTISE` → route toward remote host → default route UDP → non-loopback iface.
fn advertise_ip(remote: Option<&str>) -> String {
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
fn validate_advertise(v: &str) -> Result<(), String> {
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

fn guess_ip_toward(host: &str) -> Option<String> {
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

fn guess_local_ip() -> Option<String> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    let ip = s.local_addr().ok()?.ip();
    if ip.is_loopback() {
        return None;
    }
    Some(ip.to_string())
}

/// First non-loopback IPv4 with a default route from `/proc/net/route` (Linux).
fn guess_ip_from_proc_route() -> Option<String> {
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

/// Prefer transfer error; kill agent on failure; surface non-zero agent exit if transfer OK.
/// Bounded wait so a stuck remote agent cannot hang the local process forever.
fn finish_agent(child: &mut Child, transfer: Result<(), String>, role: &str) -> Result<(), String> {
    if transfer.is_err() {
        let _ = child.kill();
    }
    let limit = agent_wait_timeout();
    let deadline = Instant::now() + limit;
    let st = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Ok(s),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(format!(
                    "{role} wait timed out after {}s",
                    limit.as_secs()
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(e) => break Err(format!("{role} wait: {e}")),
        }
    };
    match (transfer, st) {
        (Err(e), _) => Err(e),
        (Ok(()), Ok(s)) if s.success() => Ok(()),
        (Ok(()), Ok(s)) => Err(format!("{role} exited {s}")),
        (Ok(()), Err(e)) => Err(e),
    }
}

fn agent_wait_timeout() -> Duration {
    env::var("BBX_AGENT_WAIT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(io_timeout)
}

// --- ssh -------------------------------------------------------------------

fn ssh_spawn(remote: &str, remote_cmd: &str) -> Result<Child, String> {
    Command::new("ssh")
        .arg(remote)
        .arg(remote_cmd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("ssh: {e}"))
}

/// Read PORT, optional KEY, optional RESUME from remote agent stdout.
fn ssh_start_banner(
    remote: &str,
    remote_cmd: &str,
    expect_key: bool,
    expect_resume: bool,
) -> Result<(Child, u16, Option<[u8; 32]>, u64), String> {
    let mut child = Command::new("ssh")
        .arg(remote)
        .arg(remote_cmd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("ssh: {e}"))?;

    let mut stdout = child.stdout.take().ok_or("ssh stdout")?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 256];
    let mut need = 1;
    if expect_key {
        need += 1;
    }
    if expect_resume {
        need += 1;
    }
    loop {
        let n = stdout.read(&mut tmp).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.iter().filter(|&&b| b == b'\n').count() >= need || buf.len() > 768 {
            break;
        }
    }
    thread::spawn(move || {
        let mut sink = io::sink();
        let _ = io::copy(&mut stdout, &mut sink);
    });

    let s = String::from_utf8_lossy(&buf);
    let mut port: Option<u16> = None;
    let mut key: Option<[u8; 32]> = None;
    let mut resume_from: u64 = 0;
    for line in s.lines() {
        let mut w = line.split_whitespace();
        match w.next() {
            Some("PORT") => {
                port = Some(
                    w.next()
                        .ok_or("PORT missing value")?
                        .parse()
                        .map_err(|_| "bad PORT")?,
                );
            }
            Some("KEY") => {
                key = Some(parse_key(w.next().ok_or("KEY missing value")?)?);
            }
            Some("RESUME") => {
                resume_from = w
                    .next()
                    .ok_or("RESUME missing value")?
                    .parse()
                    .map_err(|_| "bad RESUME")?;
            }
            _ => {}
        }
    }
    let port = port.ok_or_else(|| format!("remote did not print PORT: {s:?}"))?;
    if expect_key && key.is_none() {
        return Err(format!("remote did not print KEY (upgrade remote bbx?): {s:?}"));
    }
    Ok((child, port, key, resume_from))
}

// --- transfer engine -------------------------------------------------------

fn print_listen_banner(port: u16, crypt: bool, key: &Option<[u8; 32]>, resume_from: Option<u64>) {
    println!("PORT {port}");
    if crypt {
        let k = key.expect("crypt without key");
        println!("KEY {}", hex(&k));
    }
    if let Some(r) = resume_from {
        println!("RESUME {r}");
    }
    let _ = io::stdout().flush();
}

fn existing_len(path: &str) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn run_sink_listen(
    listen: &str,
    port_range: Option<(u16, u16)>,
    out: &str,
    streams: usize,
    wnd: usize,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume: bool,
    json: bool,
    progress: u64,
    rate: u64,
) -> Result<(), String> {
    let key = if crypt {
        Some(key.unwrap_or_else(gen_key))
    } else {
        None
    };
    let have = if resume { Some(existing_len(out)) } else { None };
    if !crypt {
        cleartext_allowed(listen)?;
    }
    let listener = bind_listener(listen, port_range)?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    print_listen_banner(port, crypt, &key, have);
    run_sink_with_listener(
        listener, out, streams, wnd, check, progress, crypt, key, resume, json, rate,
    )
}

fn run_sink_connect(
    addr: &str,
    out: &str,
    streams: usize,
    wnd: usize,
    check: bool,
    progress: u64,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume: bool,
    json: bool,
    rate: u64,
) -> Result<(), String> {
    if crypt && key.is_none() {
        return Err("encrypt needs -k KEY (from peer KEY line)".into());
    }
    if !crypt {
        cleartext_allowed(addr)?;
    }
    let conns = dial_streams(addr, streams, wnd, key.as_ref())?;
    finish_sink(conns, out, streams, check, progress, crypt, key, resume, json, rate)
}

fn run_sink_with_listener(
    listener: TcpListener,
    out: &str,
    streams: usize,
    wnd: usize,
    check: bool,
    progress: u64,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume: bool,
    json: bool,
    rate: u64,
) -> Result<(), String> {
    if !crypt {
        let la = listener
            .local_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        cleartext_allowed(&la)?;
    }
    let conns = accept_streams(&listener, streams, wnd, "sink", key.as_ref())?;
    finish_sink(conns, out, streams, check, progress, crypt, key, resume, json, rate)
}

/// On failed transfer after dest was resized: remove (fresh) or shrink to trusted prefix (resume).
fn sink_fail_cleanup(out: &str, resume_from: u64) {
    if resume_from == 0 {
        let _ = std::fs::remove_file(out);
    } else if let Ok(f) = OpenOptions::new().write(true).open(out) {
        let _ = f.set_len(resume_from);
    }
}

fn finish_sink(
    mut conns: Vec<TcpStream>,
    out: &str,
    streams_hint: usize,
    check: bool,
    progress: u64,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume: bool,
    json: bool,
    rate: u64,
) -> Result<(), String> {
    let mut ctrl = conns.remove(0);
    let mut magic = [0u8; 4];
    ctrl.read_exact(&mut magic).map_err(|e| e.to_string())?;
    if &magic != MAGIC {
        return Err(format!("bad magic {:?} (need BBX2; upgrade both ends)", magic));
    }
    let flags = read_u32(&mut ctrl)?;
    let size = read_u64(&mut ctrl)?;
    let n = read_u32(&mut ctrl)? as usize;
    if n == 0 || n > 64 {
        return Err("bad stream count".into());
    }
    let want_check = flags & FLAG_BLAKE3 != 0;
    let want_crypt = flags & FLAG_CRYPT != 0;
    let want_resume = flags & FLAG_RESUME != 0;
    let want_preserve = flags & FLAG_PRESERVE != 0;
    let resume_from = if want_resume {
        read_u64(&mut ctrl)?
    } else {
        0
    };
    if want_crypt != crypt {
        return Err(format!(
            "crypt mismatch: local={} peer={}",
            crypt, want_crypt
        ));
    }
    if want_crypt && key.is_none() {
        return Err("peer sent FLAG_CRYPT but no session key".into());
    }
    // Per-transfer salt (FLAG_CRYPT): derive AEAD key so reused PSKs never share nonce space.
    let (aead_key, salt, frame_aad_bytes) = if want_crypt {
        let mut salt = [0u8; 32];
        ctrl.read_exact(&mut salt).map_err(|e| e.to_string())?;
        let ak = derive_aead_key(key.as_ref().unwrap(), &salt);
        let aad = frame_aad(flags, size, n as u32, resume_from, &salt);
        (Some(ak), Some(salt), Some(aad))
    } else {
        (None, None, None)
    };
    if resume_from > size {
        return Err(format!("resume_from {resume_from} > size {size}"));
    }
    let _ = resume; // peer may resume even if local -A unset
    // C12: local -c/-C vs peer FLAG_BLAKE3
    if check && !want_check {
        return Err(
            "source did not enable BLAKE3 (need matching -c on source, or pass -C to skip check)"
                .into(),
        );
    }
    if !check && want_check && !json {
        eprintln!("bbx: warning: local -C ignored (source sent FLAG_BLAKE3; verifying)");
    }
    // Resume trusts prefix length; full-file BLAKE3 is the integrity backstop.
    if resume_from > 0 && !want_check {
        return Err(
            "resume requires BLAKE3 (-c): prefix is not re-hashed alone; refuse unsafe resume"
                .into(),
        );
    }
    let streams = n;
    if streams_hint != 0 && streams_hint != streams {
        return Err(format!(
            "stream count mismatch: local -s {streams_hint}, peer {streams}"
        ));
    }
    let mut all = Vec::with_capacity(streams);
    all.push(ctrl);
    all.append(&mut conns);
    if all.len() != streams {
        return Err(format!("expected {streams} streams, got {}", all.len()));
    }

    // Sensitive control fields: clear when !crypt; AEAD-sealed when crypt (F8).
    let (expect_hash, meta_mode, meta_mtime) = if want_crypt {
        let aead = aead_key.as_ref().unwrap();
        let aad = frame_aad_bytes.as_ref().unwrap();
        let clen = read_u32(&mut all[0])? as usize;
        if clen > 256 {
            return Err(format!("bad sealed control len {clen}"));
        }
        let mut ct = vec![0u8; clen];
        all[0]
            .read_exact(&mut ct)
            .map_err(|e| e.to_string())?;
        let pt = aead_decrypt(aead, 0, CONTROL_COUNTER, &ct, aad)?;
        let mut off = 0usize;
        let mut expect_hash = [0u8; 32];
        let mut have_hash = false;
        if want_check {
            if pt.len() < off + 32 {
                return Err("sealed control short (hash)".into());
            }
            expect_hash.copy_from_slice(&pt[off..off + 32]);
            off += 32;
            have_hash = true;
        }
        let (meta_mode, meta_mtime) = if want_preserve {
            if pt.len() < off + 12 {
                return Err("sealed control short (preserve)".into());
            }
            let mode = u32::from_le_bytes(pt[off..off + 4].try_into().unwrap());
            let mtime = u64::from_le_bytes(pt[off + 4..off + 12].try_into().unwrap());
            (Some(mode), Some(mtime))
        } else {
            (None, None)
        };
        let _ = have_hash;
        let _ = salt;
        (
            if want_check { Some(expect_hash) } else { None },
            meta_mode,
            meta_mtime,
        )
    } else {
        let mut expect_hash = None;
        if want_check {
            let mut h = [0u8; 32];
            all[0].read_exact(&mut h).map_err(|e| e.to_string())?;
            expect_hash = Some(h);
        }
        let (meta_mode, meta_mtime) = if want_preserve {
            let mode = read_u32(&mut all[0])?;
            let mtime = read_u64(&mut all[0])?;
            (Some(mode), Some(mtime))
        } else {
            (None, None)
        };
        (expect_hash, meta_mode, meta_mtime)
    };

    let have = existing_len(out);
    if resume_from > 0 {
        if have < resume_from {
            return Err(format!(
                "local file shorter than resume_from ({have} < {resume_from})"
            ));
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(resume_from == 0)
        .open(out)
        .map_err(|e| e.to_string())?;
    if resume_from > 0 && have > resume_from {
        file.set_len(resume_from).map_err(|e| e.to_string())?;
    }
    file.set_len(size).map_err(|e| e.to_string())?;

    let transfer = (|| -> Result<(), String> {
        let remaining = size - resume_from;
        let ranges = split_ranges(remaining, streams)
            .into_iter()
            .map(|(a, b)| (a + resume_from, b + resume_from))
            .collect::<Vec<_>>();
        let file = Arc::new(file);
        let got = Arc::new(AtomicU64::new(resume_from));
        let t0 = Instant::now();
        let key = aead_key.map(Arc::new);
        let aad = frame_aad_bytes.map(Arc::new);
        let rate_start = Instant::now();
        if progress > 0 {
            let g = Arc::clone(&got);
            thread::spawn(move || loop {
                thread::sleep(Duration::from_secs(progress.max(1)));
                let n = g.load(Ordering::Relaxed);
                report_progress(n, size, t0, json);
                if n >= size {
                    break;
                }
            });
        }

        let abort = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        for (i, mut sock) in all.into_iter().enumerate() {
            let (start, end) = ranges[i];
            let f = Arc::clone(&file);
            let g = Arc::clone(&got);
            let k = key.clone();
            let a = aad.clone();
            let ab = Arc::clone(&abort);
            handles.push(thread::spawn(move || -> Result<(), String> {
                let r = recv_range(
                    &mut sock,
                    &f,
                    start,
                    end,
                    i as u32,
                    k.as_deref(),
                    a.as_deref().map(|v| v.as_slice()),
                    &g,
                    &ab,
                    rate,
                    rate_start,
                );
                if r.is_err() {
                    ab.store(true, Ordering::Relaxed);
                }
                r
            }));
        }
        for h in handles {
            h.join().map_err(|_| "thread panic".to_string())??;
        }

        if let Some(expect_hash) = expect_hash {
            if !json {
                eprint!("\nbbx: verifying BLAKE3… ");
                let _ = io::stderr().flush();
            }
            let got_hash = hash_file(out)?;
            if got_hash != expect_hash {
                return Err(format!(
                    "checksum mismatch: expected {} got {}",
                    hex(&expect_hash),
                    hex(&got_hash)
                ));
            }
            if !json {
                eprintln!("ok");
            }
        }
        if let (Some(mode), Some(mtime)) = (meta_mode, meta_mtime) {
            apply_preserve(out, mode, mtime)?;
        }
        if progress > 0 {
            report_progress(size, size, t0, json);
            if !json {
                eprintln!();
            }
        }
        if json {
            println!(
                r#"{{"event":"done","bytes":{size},"total":{size},"resumed_from":{resume_from}}}"#
            );
        }
        Ok(())
    })();

    if transfer.is_err() {
        sink_fail_cleanup(out, resume_from);
    }
    transfer
}

fn run_source_connect(
    addr: &str,
    input: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume_from: u64,
    json: bool,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    if crypt && key.is_none() {
        return Err("encrypt needs session KEY from peer".into());
    }
    if !crypt {
        cleartext_allowed(addr)?;
    }
    let conns = dial_streams(addr, streams, wnd, key.as_ref())?;
    finish_source(
        conns, input, streams, progress, check, crypt, key, resume_from, json, preserve, rate,
    )
}

fn run_source_listen(
    listen: &str,
    port_range: Option<(u16, u16)>,
    input: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume_from: u64,
    json: bool,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    let key = if crypt {
        Some(key.unwrap_or_else(gen_key))
    } else {
        None
    };
    if !crypt {
        cleartext_allowed(listen)?;
    }
    let listener = bind_listener(listen, port_range)?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    print_listen_banner(port, crypt, &key, None);
    run_source_with_listener(
        listener, input, streams, wnd, progress, check, crypt, key, resume_from, json, preserve,
        rate,
    )
}

fn run_source_with_listener(
    listener: TcpListener,
    input: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume_from: u64,
    json: bool,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    if !crypt {
        let la = listener
            .local_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        cleartext_allowed(&la)?;
    }
    let conns = accept_streams(&listener, streams, wnd, "source", key.as_ref())?;
    finish_source(
        conns, input, streams, progress, check, crypt, key, resume_from, json, preserve, rate,
    )
}

fn finish_source(
    mut conns: Vec<TcpStream>,
    input: &str,
    streams: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume_from: u64,
    json: bool,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    if conns.len() != streams {
        return Err(format!("expected {streams} streams, got {}", conns.len()));
    }
    if crypt && key.is_none() {
        return Err("encrypt needs key".into());
    }
    let file = File::open(input).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    let size = meta.len();
    if resume_from > size {
        return Err(format!("resume_from {resume_from} > file size {size}"));
    }
    // Always send the control header (even when remaining == 0) so the sink can
    // create/set_len, verify BLAKE3, and apply --preserve. Never trust length-only skip.

    let hash = if check {
        if !json {
            eprint!("bbx: hashing BLAKE3… ");
            let _ = io::stderr().flush();
        }
        let h = hash_file(input)?;
        if !json {
            eprintln!("ok");
        }
        Some(h)
    } else {
        None
    };

    let file_meta = if preserve {
        Some(file_mode_mtime(&meta)?)
    } else {
        None
    };

    let mut ctrl = &mut conns[0];
    ctrl.write_all(MAGIC).map_err(|e| e.to_string())?;
    let mut flags = 0u32;
    if check {
        flags |= FLAG_BLAKE3;
    }
    if crypt {
        flags |= FLAG_CRYPT;
    }
    if resume_from > 0 {
        flags |= FLAG_RESUME;
    }
    if preserve {
        flags |= FLAG_PRESERVE;
    }
    if resume_from > 0 && !check {
        return Err(
            "resume requires BLAKE3 (-c): refuse sending resume without integrity".into(),
        );
    }
    write_u32(&mut ctrl, flags)?;
    write_u64(&mut ctrl, size)?;
    write_u32(&mut ctrl, streams as u32)?;
    if resume_from > 0 {
        write_u64(&mut ctrl, resume_from)?;
    }
    // Per-transfer salt under FLAG_CRYPT → unique AEAD key even if PSK is reused.
    let (aead_key, frame_aad_bytes) = if crypt {
        let salt = gen_key();
        ctrl.write_all(&salt).map_err(|e| e.to_string())?;
        let ak = derive_aead_key(key.as_ref().unwrap(), &salt);
        let aad = frame_aad(flags, size, streams as u32, resume_from, &salt);
        // Seal blake3 + preserve under AEAD (F8); salt stays clear (needed to derive).
        let mut plain = Vec::new();
        if let Some(h) = hash {
            plain.extend_from_slice(&h);
        }
        if let Some((mode, mtime)) = file_meta {
            plain.extend_from_slice(&mode.to_le_bytes());
            plain.extend_from_slice(&mtime.to_le_bytes());
        }
        // Always send sealed blob when crypt (may be empty pt → tag only) so wire is uniform.
        let ct = aead_encrypt(&ak, 0, CONTROL_COUNTER, &plain, &aad)?;
        write_u32(&mut ctrl, ct.len() as u32)?;
        ctrl.write_all(&ct).map_err(|e| e.to_string())?;
        (Some(ak), Some(aad))
    } else {
        if let Some(h) = hash {
            ctrl.write_all(&h).map_err(|e| e.to_string())?;
        }
        if let Some((mode, mtime)) = file_meta {
            write_u32(&mut ctrl, mode)?;
            write_u64(&mut ctrl, mtime)?;
        }
        (None, None)
    };

    let remaining = size - resume_from;
    let ranges = split_ranges(remaining, streams)
        .into_iter()
        .map(|(a, b)| (a + resume_from, b + resume_from))
        .collect::<Vec<_>>();
    let sent = Arc::new(AtomicU64::new(resume_from));
    let t0 = Instant::now();
    let rate_start = Instant::now();
    let file = Arc::new(file);
    let key = aead_key.map(Arc::new);
    let aad = frame_aad_bytes.map(Arc::new);

    if progress > 0 {
        let sent_p = Arc::clone(&sent);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(progress.max(1)));
            let n = sent_p.load(Ordering::Relaxed);
            report_progress(n, size, t0, json);
            if n >= size {
                break;
            }
        });
    }

    let abort = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    for (i, mut sock) in conns.into_iter().enumerate() {
        let (start, end) = ranges[i];
        let f = Arc::clone(&file);
        let sent_c = Arc::clone(&sent);
        let k = key.clone();
        let a = aad.clone();
        let ab = Arc::clone(&abort);
        handles.push(thread::spawn(move || -> Result<(), String> {
            let r = send_range(
                &mut sock,
                &f,
                start,
                end,
                i as u32,
                k.as_deref(),
                a.as_deref().map(|v| v.as_slice()),
                &sent_c,
                &ab,
                rate,
                rate_start,
            );
            if r.is_err() {
                ab.store(true, Ordering::Relaxed);
            }
            r
        }));
    }
    for h in handles {
        h.join().map_err(|_| "thread panic".to_string())??;
    }
    report_progress(size, size, t0, json);
    let elapsed = t0.elapsed().as_secs_f64().max(0.001);
    if json {
        println!(
            r#"{{"event":"done","bytes":{size},"total":{size},"secs":{elapsed:.3},"resumed_from":{resume_from},"encrypted":{}}}"#,
            if crypt { "true" } else { "false" }
        );
    } else {
        eprintln!(
            "\nbbx: done {} bytes in {:.2}s ({:.1} MB/s){}{}",
            size,
            elapsed,
            size as f64 / elapsed / 1024.0 / 1024.0,
            if crypt { " [encrypted]" } else { "" },
            if resume_from > 0 {
                format!(" [resumed from {resume_from}]")
            } else {
                String::new()
            }
        );
    }
    Ok(())
}

// --- crypto frames ---------------------------------------------------------

fn make_nonce(stream_id: u32, counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&stream_id.to_le_bytes());
    n[4..12].copy_from_slice(&counter.to_le_bytes());
    *Nonce::from_slice(&n)
}

/// Sleep so cumulative `total` bytes stay near `rate` bytes/sec since `t0`.
fn throttle(rate: u64, total: u64, t0: Instant) {
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

fn send_range(
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

fn recv_range(
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

fn file_mode_mtime(meta: &std::fs::Metadata) -> Result<(u32, u64), String> {
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

fn apply_preserve(path: &str, mode: u32, mtime: u64) -> Result<(), String> {
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

// --- util ------------------------------------------------------------------

fn hash_file(path: &str) -> Result<[u8; 32], String> {
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn report_progress(n: u64, size: u64, t0: Instant, json: bool) {
    if json {
        let elapsed = t0.elapsed().as_secs_f64().max(0.001);
        let rate = (n as f64 / elapsed) / (1024.0 * 1024.0);
        println!(
            r#"{{"event":"progress","bytes":{n},"total":{size},"rate_mbps":{rate:.3}}}"#
        );
    } else {
        eprint_progress(n, size, t0);
    }
}

fn eprint_progress(n: u64, size: u64, t0: Instant) {
    let elapsed = t0.elapsed().as_secs_f64().max(0.001);
    let pct = if size == 0 {
        100.0
    } else {
        (n as f64 / size as f64) * 100.0
    };
    let rate = n as f64 / elapsed / 1024.0 / 1024.0;
    let filled = ((pct / 100.0) * 24.0).round() as usize;
    let bar: String = std::iter::repeat_n('#', filled.min(24))
        .chain(std::iter::repeat_n('-', 24usize.saturating_sub(filled)))
        .collect();
    let eta = if rate > 0.01 && n < size {
        let left = (size - n) as f64 / (rate * 1024.0 * 1024.0);
        format!(" ETA {left:.0}s")
    } else {
        String::new()
    };
    eprint!("\rbbx: [{bar}] {pct:5.1}%  {rate:5.1} MB/s{eta}    ");
    let _ = io::stderr().flush();
}

fn split_ranges(size: u64, n: usize) -> Vec<(u64, u64)> {
    let n = n as u64;
    let base = size / n;
    let mut rem = size % n;
    let mut out = Vec::with_capacity(n as usize);
    let mut start = 0u64;
    for _ in 0..n {
        let extra = if rem > 0 {
            rem -= 1;
            1
        } else {
            0
        };
        let end = start + base + extra;
        out.push((start, end));
        start = end;
    }
    out
}

fn read_at_full(f: &File, buf: &mut [u8], mut off: u64) -> Result<(), String> {
    let mut got = 0;
    while got < buf.len() {
        #[cfg(unix)]
        let n = f.read_at(&mut buf[got..], off).map_err(|e| e.to_string())?;
        #[cfg(windows)]
        let n = f.seek_read(&mut buf[got..], off).map_err(|e| e.to_string())?;
        #[cfg(not(any(unix, windows)))]
        let n = {
            use std::io::{Read, Seek, SeekFrom};
            let mut f2 = f.try_clone().map_err(|e| e.to_string())?;
            f2.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
            f2.read(&mut buf[got..]).map_err(|e| e.to_string())?
        };
        if n == 0 {
            return Err("unexpected EOF".into());
        }
        got += n;
        off += n as u64;
    }
    Ok(())
}

fn write_at_full(f: &File, buf: &[u8], mut off: u64) -> Result<(), String> {
    let mut put = 0;
    while put < buf.len() {
        #[cfg(unix)]
        let n = f.write_at(&buf[put..], off).map_err(|e| e.to_string())?;
        #[cfg(windows)]
        let n = f.seek_write(&buf[put..], off).map_err(|e| e.to_string())?;
        #[cfg(not(any(unix, windows)))]
        let n = {
            use std::io::{Seek, SeekFrom, Write};
            let mut f2 = f.try_clone().map_err(|e| e.to_string())?;
            f2.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
            f2.write(&buf[put..]).map_err(|e| e.to_string())?
        };
        if n == 0 {
            return Err("short write".into());
        }
        put += n;
        off += n as u64;
    }
    Ok(())
}

fn io_timeout() -> Duration {
    let secs = env::var("BBX_IO_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(IO_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Wrap a socket error with stream context, and name a timeout for what it is.
/// A read/write timeout surfaces as WouldBlock (EAGAIN) on Unix.
fn io_err(stream_id: u32, op: &str, e: String) -> String {
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
fn set_accept_timeout(l: &TcpListener) {
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
fn set_accept_timeout(_l: &TcpListener) {}

fn accept_err(role: &str, i: usize, e: std::io::Error) -> String {
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
fn dial_streams(
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
fn peer_allowlist() -> Option<Vec<std::net::IpAddr>> {
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

fn accept_streams(
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

fn tune(s: &TcpStream, wnd: usize) {
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

fn read_u64(r: &mut impl Read) -> Result<u64, String> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes(b))
}
fn read_u32(r: &mut impl Read) -> Result<u32, String> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u32::from_le_bytes(b))
}
fn write_u32(w: &mut impl Write, v: u32) -> Result<(), String> {
    w.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}
fn write_u64(w: &mut impl Write, v: u64) -> Result<(), String> {
    w.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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

}
