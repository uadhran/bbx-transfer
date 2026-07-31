//! bbx — multi-stream bulk copy (BBX2).
//!
//! sink/source/cp with: -s -w -P -c|-C -e|-E -k -A (resume) -J (json) -z
//! See SPEC.md.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::FileExt;
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
         cp defaults: -c -e on. -A resumes partial dest.\n\
         BBX_REMOTE=  BBX_ADVERTISE=  BBX_KEY=  BBX_PORT_RANGE=  BBX_IO_TIMEOUT_SECS=\n"
    );
    std::process::exit(code);
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
    bind_listener("0.0.0.0:0", range)
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
        ),
        (None, Some(a)) => {
            run_sink_connect(a, &out, f.streams, f.wnd, f.check, crypt, key, f.resume, f.json)
        }
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
        ),
        (Some(l), None) => run_source_listen(
            l, f.port_range, &input, f.streams, f.wnd, f.progress, f.check, crypt, key, rf, f.json,
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

    match (is_remote_spec(src), is_remote_spec(dest)) {
        (false, true) => {
            let (remote, rpath) = split_host_path(dest)?;
            if recurse {
                cp_push_tree(
                    &bin, remote, rpath, src, s, w, p, check, crypt, resume, json, rev, pr,
                    fixed_key,
                )
            } else if rev {
                cp_push_reverse(
                    &bin, remote, rpath, src, s, w, p, check, crypt, resume, json, pr, fixed_key,
                )
            } else {
                cp_push_forward(
                    &bin, remote, rpath, src, s, w, p, check, crypt, resume, json, pr, fixed_key,
                )
            }
        }
        (true, false) => {
            let (remote, rpath) = split_host_path(src)?;
            if recurse {
                cp_pull_tree(
                    &bin, remote, rpath, dest, s, w, p, check, crypt, resume, json, rev, pr,
                    fixed_key,
                )
            } else if rev {
                cp_pull_reverse(
                    &bin, remote, rpath, dest, s, w, p, check, crypt, resume, json, pr, fixed_key,
                )
            } else {
                cp_pull_forward(
                    &bin, remote, rpath, dest, s, w, p, check, crypt, resume, json, pr, fixed_key,
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
    match s.rfind(':') {
        None => false,
        Some(i) => {
            let host = &s[..i];
            !host.is_empty() && !host.contains('/')
        }
    }
}

fn split_host_path(spec: &str) -> Result<(&str, &str), String> {
    let idx = spec.rfind(':').ok_or("need host:path")?;
    let (host, path) = spec.split_at(idx);
    let path = &path[1..];
    if host.is_empty() || path.is_empty() {
        return Err("bad host:path".into());
    }
    Ok((host, path))
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

fn ssh_mkdir_p(remote: &str, dir: &str) -> Result<(), String> {
    let st = Command::new("ssh")
        .arg(remote)
        .arg(format!("mkdir -p {}", shell_quote(dir)))
        .stdin(Stdio::inherit())
        .status()
        .map_err(|e| format!("ssh mkdir: {e}"))?;
    if !st.success() {
        return Err(format!("mkdir -p failed for {dir}"));
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
) -> Result<(), String> {
    let root = std::path::Path::new(local_src);
    let files = walk_local_files(root)?;
    if files.is_empty() {
        return Err("no files under source directory".into());
    }
    ssh_mkdir_p(remote, rpath)?;
    if !json {
        eprintln!("bbx: push -r {} files → {}:{rpath}", files.len(), remote);
    }
    for (i, (local, rel)) in files.iter().enumerate() {
        let remote_file = join_remote(rpath, rel);
        if let Some(parent) = parent_posix(&remote_file) {
            ssh_mkdir_p(remote, &parent)?;
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
        let local_s = local.to_string_lossy();
        if rev {
            cp_push_reverse(
                bin, remote, &remote_file, &local_s, streams, wnd, progress, check, crypt,
                resume, json, port_range, fixed_key,
            )?;
        } else {
            cp_push_forward(
                bin, remote, &remote_file, &local_s, streams, wnd, progress, check, crypt,
                resume, json, port_range, fixed_key,
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
        if rev {
            cp_pull_reverse(
                bin, remote, &remote_file, &local_s, streams, wnd, progress, check, crypt,
                resume, json, port_range, fixed_key,
            )?;
        } else {
            cp_pull_forward(
                bin, remote, &remote_file, &local_s, streams, wnd, progress, check, crypt,
                resume, json, port_range, fixed_key,
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
) -> Result<(), String> {
    let ce = ce_flags(check, crypt);
    let z = z_flag(port_range);
    // Remote generates KEY (banner). Local uses banner unless -k/BBX_KEY overrides.
    // Override ≠ banner → decrypt fails closed (wrong key).
    let cmd = format!(
        "{} sink -l 0.0.0.0:0{z} -o {} -s {streams} -w {wnd} {ce}{}",
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
        &addr, local_src, streams, wnd, progress, check, crypt, key, resume_from, json,
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
    let kenv = key
        .as_ref()
        .map(|k| format!("BBX_KEY={} ", hex(k)))
        .unwrap_or_default();
    let cmd = format!(
        "{kenv}{} sink -a {} -o {} -s {streams} -w {wnd} {ce}{}",
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
        "{kenv}{} source -a {} -i {} -s {streams} -w {wnd} {ce}{rarg}",
        shell_quote(bin),
        shell_quote(&addr),
        shell_quote(rpath)
    );
    if !json {
        eprintln!("bbx: pull {remote}:{rpath} → {local_dst} listen={addr} resume_from={rf}");
    }
    let mut child = ssh_spawn(remote, &cmd)?;
    let r = run_sink_with_listener(
        listener, local_dst, streams, wnd, check, progress, crypt, key, resume, json,
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
) -> Result<(), String> {
    let ce = ce_flags(check, crypt);
    let z = z_flag(port_range);
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
        "{kenv}{} source -l 0.0.0.0:0{z} -i {} -s {streams} -w {wnd} {ce}{rarg}",
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
    let r = run_sink_connect(&addr, local_dst, streams, wnd, check, crypt, key, resume, json);
    let _ = progress;
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
            return v.to_string();
        }
    }
    if let Some(r) = remote {
        if let Some(ip) = guess_ip_toward(host_only(r)) {
            return ip;
        }
    }
    guess_local_ip()
        .or_else(guess_ip_from_proc_route)
        .unwrap_or_else(|| "127.0.0.1".into())
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
fn finish_agent(child: &mut Child, transfer: Result<(), String>, role: &str) -> Result<(), String> {
    if transfer.is_err() {
        let _ = child.kill();
    }
    let st = child.wait();
    match (transfer, st) {
        (Err(e), _) => Err(e),
        (Ok(()), Ok(s)) if s.success() => Ok(()),
        (Ok(()), Ok(s)) => Err(format!("{role} exited {s}")),
        (Ok(()), Err(e)) => Err(format!("{role} wait: {e}")),
    }
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
) -> Result<(), String> {
    let key = if crypt {
        Some(key.unwrap_or_else(gen_key))
    } else {
        None
    };
    let have = if resume { Some(existing_len(out)) } else { None };
    let listener = bind_listener(listen, port_range)?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    print_listen_banner(port, crypt, &key, have);
    run_sink_with_listener(listener, out, streams, wnd, check, 0, crypt, key, resume, json)
}

fn run_sink_connect(
    addr: &str,
    out: &str,
    streams: usize,
    wnd: usize,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume: bool,
    json: bool,
) -> Result<(), String> {
    if crypt && key.is_none() {
        return Err("encrypt needs -k KEY (from peer KEY line)".into());
    }
    let conns = dial_streams(addr, streams, wnd)?;
    finish_sink(conns, out, streams, check, 0, crypt, key, resume, json)
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
) -> Result<(), String> {
    let conns = accept_streams(&listener, streams, wnd, "sink")?;
    finish_sink(conns, out, streams, check, progress, crypt, key, resume, json)
}

fn finish_sink(
    mut conns: Vec<TcpStream>,
    out: &str,
    streams_hint: usize,
    _check: bool,
    progress: u64,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume: bool,
    json: bool,
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
    if resume_from > size {
        return Err(format!("resume_from {resume_from} > size {size}"));
    }
    if resume_from > 0 && !resume {
        // peer resumed; sink must accept append open
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

    let mut expect_hash = [0u8; 32];
    if want_check {
        all[0]
            .read_exact(&mut expect_hash)
            .map_err(|e| e.to_string())?;
    }

    let have = existing_len(out);
    if resume_from > 0 {
        if have < resume_from {
            return Err(format!(
                "local file shorter than resume_from ({have} < {resume_from})"
            ));
        }
        // keep prefix; grow/shrink to final size later
    }
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(resume_from == 0)
        .open(out)
        .map_err(|e| e.to_string())?;
    file.set_len(size).map_err(|e| e.to_string())?;

    let remaining = size - resume_from;
    let ranges = split_ranges(remaining, streams)
        .into_iter()
        .map(|(a, b)| (a + resume_from, b + resume_from))
        .collect::<Vec<_>>();
    let file = Arc::new(file);
    let got = Arc::new(AtomicU64::new(resume_from));
    let t0 = Instant::now();
    let key = key.map(Arc::new);
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
        let ab = Arc::clone(&abort);
        handles.push(thread::spawn(move || -> Result<(), String> {
            let r = recv_range(&mut sock, &f, start, end, i as u32, k.as_deref(), &g, &ab);
            if r.is_err() {
                ab.store(true, Ordering::Relaxed);
            }
            r
        }));
    }
    for h in handles {
        h.join().map_err(|_| "thread panic".to_string())??;
    }

    if want_check {
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
) -> Result<(), String> {
    if crypt && key.is_none() {
        return Err("encrypt needs session KEY from peer".into());
    }
    let conns = dial_streams(addr, streams, wnd)?;
    finish_source(conns, input, streams, progress, check, crypt, key, resume_from, json)
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
) -> Result<(), String> {
    let key = if crypt {
        Some(key.unwrap_or_else(gen_key))
    } else {
        None
    };
    let listener = bind_listener(listen, port_range)?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    print_listen_banner(port, crypt, &key, None);
    run_source_with_listener(
        listener, input, streams, wnd, progress, check, crypt, key, resume_from, json,
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
) -> Result<(), String> {
    let conns = accept_streams(&listener, streams, wnd, "source")?;
    finish_source(conns, input, streams, progress, check, crypt, key, resume_from, json)
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
) -> Result<(), String> {
    if conns.len() != streams {
        return Err(format!("expected {streams} streams, got {}", conns.len()));
    }
    if crypt && key.is_none() {
        return Err("encrypt needs key".into());
    }
    let file = File::open(input).map_err(|e| e.to_string())?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    if resume_from > size {
        return Err(format!("resume_from {resume_from} > file size {size}"));
    }
    // Only short-circuit a genuine resume that is already complete. For a
    // real 0-byte file resume_from == size == 0, and we must still send the
    // header so the sink can create + set_len(0) the destination.
    if resume_from == size && resume_from > 0 {
        if json {
            println!(r#"{{"event":"done","bytes":{size},"total":{size},"resumed_from":{resume_from},"skipped":true}}"#);
        } else {
            eprintln!("bbx: already complete ({size} bytes)");
        }
        return Ok(());
    }

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
    write_u32(&mut ctrl, flags)?;
    write_u64(&mut ctrl, size)?;
    write_u32(&mut ctrl, streams as u32)?;
    if resume_from > 0 {
        write_u64(&mut ctrl, resume_from)?;
    }
    if let Some(h) = hash {
        ctrl.write_all(&h).map_err(|e| e.to_string())?;
    }

    let remaining = size - resume_from;
    let ranges = split_ranges(remaining, streams)
        .into_iter()
        .map(|(a, b)| (a + resume_from, b + resume_from))
        .collect::<Vec<_>>();
    let sent = Arc::new(AtomicU64::new(resume_from));
    let t0 = Instant::now();
    let file = Arc::new(file);
    let key = key.map(Arc::new);

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
        let ab = Arc::clone(&abort);
        handles.push(thread::spawn(move || -> Result<(), String> {
            let r = send_range(&mut sock, &f, start, end, i as u32, k.as_deref(), &sent_c, &ab);
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

fn send_range(
    sock: &mut TcpStream,
    f: &File,
    start: u64,
    end: u64,
    stream_id: u32,
    key: Option<&[u8; 32]>,
    sent: &AtomicU64,
    abort: &AtomicBool,
) -> Result<(), String> {
    let mut off = start;
    let mut left = end - start;
    let mut buf = vec![0u8; if key.is_some() { CRYPT_PT } else { CHUNK }];
    let mut counter = 0u64;
    let cipher = key.map(|k| ChaCha20Poly1305::new_from_slice(k).expect("key"));

    while left > 0 {
        if abort.load(Ordering::Relaxed) {
            return Err(format!("stream {stream_id} aborted (peer stream failed)"));
        }
        let want = left.min(buf.len() as u64) as usize;
        read_at_full(f, &mut buf[..want], off)?;
        if let Some(ref c) = cipher {
            let nonce = make_nonce(stream_id, counter);
            counter += 1;
            let ct = c
                .encrypt(&nonce, &buf[..want])
                .map_err(|_| "encrypt failed".to_string())?;
            write_u32(sock, ct.len() as u32).map_err(|e| io_err(stream_id, "write", e))?;
            sock.write_all(&ct).map_err(|e| io_err(stream_id, "write", e.to_string()))?;
        } else {
            sock.write_all(&buf[..want])
                .map_err(|e| io_err(stream_id, "write", e.to_string()))?;
        }
        sent.fetch_add(want as u64, Ordering::Relaxed);
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
    got: &AtomicU64,
    abort: &AtomicBool,
) -> Result<(), String> {
    let mut off = start;
    let mut left = end - start;
    let mut buf = vec![0u8; CHUNK];
    let mut counter = 0u64;
    let cipher = key.map(|k| ChaCha20Poly1305::new_from_slice(k).expect("key"));

    while left > 0 {
        if abort.load(Ordering::Relaxed) {
            return Err(format!("stream {stream_id} aborted (peer stream failed)"));
        }
        if let Some(ref c) = cipher {
            let clen = read_u32(sock).map_err(|e| io_err(stream_id, "read", e))? as usize;
            if clen > CRYPT_PT + 16 + 64 {
                return Err(format!("bad ciphertext len {clen}"));
            }
            let mut ct = vec![0u8; clen];
            sock.read_exact(&mut ct)
                .map_err(|e| io_err(stream_id, "read", e.to_string()))?;
            let nonce = make_nonce(stream_id, counter);
            counter += 1;
            let pt = c
                .decrypt(&nonce, ct.as_ref())
                .map_err(|_| "decrypt failed (wrong key or corrupt)".to_string())?;
            if pt.len() as u64 > left {
                return Err("decrypt oversize".into());
            }
            write_at_full(f, &pt, off)?;
            got.fetch_add(pt.len() as u64, Ordering::Relaxed);
            off += pt.len() as u64;
            left -= pt.len() as u64;
        } else {
            let want = left.min(buf.len() as u64) as usize;
            sock.read_exact(&mut buf[..want])
                .map_err(|e| io_err(stream_id, "read", e.to_string()))?;
            write_at_full(f, &buf[..want], off)?;
            got.fetch_add(want as u64, Ordering::Relaxed);
            off += want as u64;
            left -= want as u64;
        }
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
        let n = f.read_at(&mut buf[got..], off).map_err(|e| e.to_string())?;
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
        let n = f.write_at(&buf[put..], off).map_err(|e| e.to_string())?;
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

/// Dialer → accepter: first 4 bytes are stream id (u32 LE). Accept order is not reliable.
fn dial_streams(addr: &str, streams: usize, wnd: usize) -> Result<Vec<TcpStream>, String> {
    let dest: SocketAddr = addr.parse::<SocketAddr>().map_err(|e| e.to_string())?;
    let mut conns = Vec::with_capacity(streams);
    for i in 0..streams {
        let mut s = TcpStream::connect_timeout(&dest, CONNECT_TIMEOUT)
            .map_err(|e| format!("connect[{i}]: {e}"))?;
        tune(&s, wnd);
        write_u32(&mut s, i as u32).map_err(|e| format!("stream-id write[{i}]: {e}"))?;
        conns.push(s);
    }
    Ok(conns)
}

fn accept_streams(
    listener: &TcpListener,
    streams: usize,
    wnd: usize,
    role: &str,
) -> Result<Vec<TcpStream>, String> {
    set_accept_timeout(listener);
    let mut slots: Vec<Option<TcpStream>> = (0..streams).map(|_| None).collect();
    for i in 0..streams {
        let (mut s, _) = listener
            .accept()
            .map_err(|e| accept_err(role, i, e))?;
        tune(&s, wnd);
        let id = read_u32(&mut s).map_err(|e| format!("{role} stream-id read[{i}]: {e}"))? as usize;
        if id >= streams {
            return Err(format!(
                "{role} bad stream id {id} (expected 0..{})",
                streams.saturating_sub(1)
            ));
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
    fn remote_spec() {
        assert!(is_remote_spec("user@host:/tmp/x"));
        assert!(!is_remote_spec("/tmp/x"));
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
