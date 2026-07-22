//! bbx — multi-stream bulk copy (BBX2 + optional encrypted payload).
//!
//!   bbx sink   (-l|-a) -o FILE [-s N] [-w B] [-c|-C] [-e|-E] [-k HEX]
//!   bbx source (-a|-l) -i FILE [-s N] [-w B] [-c|-C] [-e|-E] [-k HEX] [-P SEC]
//!   bbx cp [-s N] [-w B] [-P SEC] [-c|-C] [-e|-E] [-z] SRC DEST
//!
//! See SPEC.md. Session key for -e is printed as KEY <hex> by the listener
//! (over SSH stdout) or passed with -k.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::FileExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
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
         bbx sink   (-l ADDR | -a ADDR) -o FILE [opts]\n\
         bbx source (-a ADDR | -l ADDR) -i FILE [opts]\n\
         bbx cp [opts] [-z] SRC DEST\n\n\
         opts: -s N  -w SIZE  -P SEC  -c|-C (blake3)  -e|-E (encrypt)  -k HEX\n\
         cp defaults: -c and -e on. -C / -E to disable.\n\
         -z reverse dial. BBX_REMOTE= path on remote. BBX_ADVERTISE= dial-back IP.\n\
         cargo install --path .   # or cargo install bbx (when published)\n"
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
            "--" => {
                f.rest.extend_from_slice(&args[i + 1..]);
                break;
            }
            s if s.starts_with('-') => return Err(format!("unknown flag {s}")),
            s => f.rest.push(s.to_string()),
        }
        i += 1;
    }
    Ok(f)
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

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
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

// --- commands --------------------------------------------------------------

fn cmd_sink(args: &[String]) -> Result<(), String> {
    let f = parse_flags(args)?;
    let out = f.output.ok_or("sink needs -o FILE")?;
    let key = f.key;
    let crypt = f.crypt || key.is_some();
    match (&f.listen, &f.addr) {
        (Some(l), None) => run_sink_listen(l, &out, f.streams, f.wnd, f.check, crypt, key),
        (None, Some(a)) => run_sink_connect(a, &out, f.streams, f.wnd, f.check, crypt, key),
        _ => Err("sink needs exactly one of -l ADDR or -a ADDR".into()),
    }
}

fn cmd_source(args: &[String]) -> Result<(), String> {
    let f = parse_flags(args)?;
    let input = f.input.ok_or("source needs -i FILE")?;
    let key = f.key;
    let crypt = f.crypt || key.is_some();
    match (&f.listen, &f.addr) {
        (None, Some(a)) => {
            run_source_connect(a, &input, f.streams, f.wnd, f.progress, f.check, crypt, key)
        }
        (Some(l), None) => {
            run_source_listen(l, &input, f.streams, f.wnd, f.progress, f.check, crypt, key)
        }
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
    let bin = remote_bin();
    let s = f.streams;
    let w = f.wnd;
    let p = f.progress;
    let rev = f.reverse;

    match (is_remote_spec(src), is_remote_spec(dest)) {
        (false, true) => {
            let (remote, rpath) = split_host_path(dest)?;
            if rev {
                cp_push_reverse(&bin, remote, rpath, src, s, w, p, check, crypt)
            } else {
                cp_push_forward(&bin, remote, rpath, src, s, w, p, check, crypt)
            }
        }
        (true, false) => {
            let (remote, rpath) = split_host_path(src)?;
            if rev {
                cp_pull_reverse(&bin, remote, rpath, dest, s, w, p, check, crypt)
            } else {
                cp_pull_forward(&bin, remote, rpath, dest, s, w, p, check, crypt)
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
) -> Result<(), String> {
    let ce = ce_flags(check, crypt);
    let cmd = format!(
        "{} sink -l 0.0.0.0:0 -o {} -s {streams} -w {wnd} {ce}",
        shell_quote(bin),
        shell_quote(rpath)
    );
    let (mut child, port, key) = ssh_start_banner(remote, &cmd, crypt)?;
    let host = host_only(remote);
    let addr = format!("{host}:{port}");
    eprintln!(
        "bbx: push {local_src} → {remote}:{rpath} via {addr} streams={streams} check={check} crypt={crypt}"
    );
    let r = run_source_connect(
        &addr, local_src, streams, wnd, progress, check, crypt, key,
    );
    let _ = child.wait();
    r
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
) -> Result<(), String> {
    let listener = TcpListener::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let advertise =
        env::var("BBX_ADVERTISE").unwrap_or_else(|_| guess_local_ip().unwrap_or_else(|| "127.0.0.1".into()));
    let addr = format!("{advertise}:{port}");
    let key = if crypt { Some(gen_key()) } else { None };
    let ce = ce_flags(check, crypt);
    let karg = key
        .as_ref()
        .map(|k| format!(" -k {}", hex(k)))
        .unwrap_or_default();
    let cmd = format!(
        "{} sink -a {} -o {} -s {streams} -w {wnd} {ce}{karg}",
        shell_quote(bin),
        shell_quote(&addr),
        shell_quote(rpath)
    );
    eprintln!("bbx: push -z {local_src} → {remote}:{rpath} (remote dials {addr}) crypt={crypt}");
    let mut child = ssh_spawn(remote, &cmd)?;
    let r = run_source_with_listener(
        listener, local_src, streams, wnd, progress, check, crypt, key,
    );
    let _ = child.wait();
    r
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
) -> Result<(), String> {
    let listener = TcpListener::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let advertise =
        env::var("BBX_ADVERTISE").unwrap_or_else(|_| guess_local_ip().unwrap_or_else(|| "127.0.0.1".into()));
    let addr = format!("{advertise}:{port}");
    let key = if crypt { Some(gen_key()) } else { None };
    let ce = ce_flags(check, crypt);
    let karg = key
        .as_ref()
        .map(|k| format!(" -k {}", hex(k)))
        .unwrap_or_default();
    let cmd = format!(
        "{} source -a {} -i {} -s {streams} -w {wnd} {ce}{karg}",
        shell_quote(bin),
        shell_quote(&addr),
        shell_quote(rpath)
    );
    eprintln!("bbx: pull {remote}:{rpath} → {local_dst} (remote dials {addr}) crypt={crypt}");
    let mut child = ssh_spawn(remote, &cmd)?;
    let r = run_sink_with_listener(listener, local_dst, streams, wnd, check, progress, crypt, key);
    let _ = child.wait();
    r
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
) -> Result<(), String> {
    let ce = ce_flags(check, crypt);
    let cmd = format!(
        "{} source -l 0.0.0.0:0 -i {} -s {streams} -w {wnd} {ce}",
        shell_quote(bin),
        shell_quote(rpath)
    );
    let (mut child, port, key) = ssh_start_banner(remote, &cmd, crypt)?;
    let host = host_only(remote);
    let addr = format!("{host}:{port}");
    eprintln!("bbx: pull -z {remote}:{rpath} → {local_dst} via {addr} crypt={crypt}");
    let r = run_sink_connect(&addr, local_dst, streams, wnd, check, crypt, key);
    let _ = progress;
    let _ = child.wait();
    r
}

fn host_only(remote: &str) -> &str {
    remote.rsplit('@').next().unwrap_or(remote)
}

fn guess_local_ip() -> Option<String> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    Some(s.local_addr().ok()?.ip().to_string())
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

/// Read PORT and optional KEY lines from remote agent stdout.
fn ssh_start_banner(
    remote: &str,
    remote_cmd: &str,
    expect_key: bool,
) -> Result<(Child, u16, Option<[u8; 32]>), String> {
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
    let need_lines = if expect_key { 2 } else { 1 };
    loop {
        let n = stdout.read(&mut tmp).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.iter().filter(|&&b| b == b'\n').count() >= need_lines || buf.len() > 512 {
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
            _ => {}
        }
    }
    let port = port.ok_or_else(|| format!("remote did not print PORT: {s:?}"))?;
    if expect_key && key.is_none() {
        return Err(format!("remote did not print KEY (upgrade remote bbx?): {s:?}"));
    }
    Ok((child, port, key))
}

// --- transfer engine -------------------------------------------------------

fn print_listen_banner(port: u16, crypt: bool, key: &Option<[u8; 32]>) {
    println!("PORT {port}");
    if crypt {
        let k = key.expect("crypt without key");
        println!("KEY {}", hex(&k));
    }
    let _ = io::stdout().flush();
}

fn run_sink_listen(
    listen: &str,
    out: &str,
    streams: usize,
    wnd: usize,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
) -> Result<(), String> {
    let key = if crypt {
        Some(key.unwrap_or_else(gen_key))
    } else {
        None
    };
    let listener = TcpListener::bind(listen).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    print_listen_banner(port, crypt, &key);
    run_sink_with_listener(listener, out, streams, wnd, check, 0, crypt, key)
}

fn run_sink_connect(
    addr: &str,
    out: &str,
    streams: usize,
    wnd: usize,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
) -> Result<(), String> {
    if crypt && key.is_none() {
        return Err("encrypt needs -k KEY (from peer KEY line)".into());
    }
    let dest: SocketAddr = addr.parse::<SocketAddr>().map_err(|e| e.to_string())?;
    let mut conns = Vec::with_capacity(streams);
    for i in 0..streams {
        let s = TcpStream::connect(dest).map_err(|e| format!("sink connect[{i}]: {e}"))?;
        tune(&s, wnd);
        conns.push(s);
    }
    finish_sink(conns, out, streams, check, 0, crypt, key)
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
) -> Result<(), String> {
    let mut conns = Vec::with_capacity(streams);
    for i in 0..streams {
        let (s, _) = listener
            .accept()
            .map_err(|e| format!("sink accept[{i}]: {e}"))?;
        tune(&s, wnd);
        conns.push(s);
    }
    finish_sink(conns, out, streams, check, progress, crypt, key)
}

fn finish_sink(
    mut conns: Vec<TcpStream>,
    out: &str,
    streams_hint: usize,
    _check: bool,
    progress: u64,
    crypt: bool,
    key: Option<[u8; 32]>,
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
    if want_crypt != crypt {
        return Err(format!(
            "crypt mismatch: local={} peer={}",
            crypt, want_crypt
        ));
    }
    if want_crypt && key.is_none() {
        return Err("peer sent FLAG_CRYPT but no session key".into());
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

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(out)
        .map_err(|e| e.to_string())?;
    file.set_len(size).map_err(|e| e.to_string())?;

    let ranges = split_ranges(size, streams);
    let file = Arc::new(file);
    let got = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();
    let key = key.map(Arc::new);
    if progress > 0 {
        let g = Arc::clone(&got);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(progress.max(1)));
            let n = g.load(Ordering::Relaxed);
            eprint_progress(n, size, t0);
            if n >= size {
                break;
            }
        });
    }

    let mut handles = Vec::new();
    for (i, mut sock) in all.into_iter().enumerate() {
        let (start, end) = ranges[i];
        let f = Arc::clone(&file);
        let g = Arc::clone(&got);
        let k = key.clone();
        handles.push(thread::spawn(move || -> Result<(), String> {
            recv_range(&mut sock, &f, start, end, i as u32, k.as_deref(), &g)
        }));
    }
    for h in handles {
        h.join().map_err(|_| "thread panic".to_string())??;
    }

    if want_check {
        eprint!("\nbbx: verifying BLAKE3… ");
        let _ = io::stderr().flush();
        let got_hash = hash_file(out)?;
        if got_hash != expect_hash {
            return Err(format!(
                "checksum mismatch: expected {} got {}",
                hex(&expect_hash),
                hex(&got_hash)
            ));
        }
        eprintln!("ok");
    }
    if progress > 0 {
        eprint_progress(size, size, t0);
        eprintln!();
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
) -> Result<(), String> {
    if crypt && key.is_none() {
        return Err("encrypt needs session KEY from peer".into());
    }
    let dest: SocketAddr = addr.parse::<SocketAddr>().map_err(|e| e.to_string())?;
    let mut conns = Vec::with_capacity(streams);
    for i in 0..streams {
        let s = TcpStream::connect(dest).map_err(|e| format!("source connect[{i}]: {e}"))?;
        tune(&s, wnd);
        conns.push(s);
    }
    finish_source(conns, input, streams, progress, check, crypt, key)
}

fn run_source_listen(
    listen: &str,
    input: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
) -> Result<(), String> {
    let key = if crypt {
        Some(key.unwrap_or_else(gen_key))
    } else {
        None
    };
    let listener = TcpListener::bind(listen).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    print_listen_banner(port, crypt, &key);
    run_source_with_listener(listener, input, streams, wnd, progress, check, crypt, key)
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
) -> Result<(), String> {
    let mut conns = Vec::with_capacity(streams);
    for i in 0..streams {
        let (s, _) = listener
            .accept()
            .map_err(|e| format!("source accept[{i}]: {e}"))?;
        tune(&s, wnd);
        conns.push(s);
    }
    finish_source(conns, input, streams, progress, check, crypt, key)
}

fn finish_source(
    mut conns: Vec<TcpStream>,
    input: &str,
    streams: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
) -> Result<(), String> {
    if conns.len() != streams {
        return Err(format!("expected {streams} streams, got {}", conns.len()));
    }
    if crypt && key.is_none() {
        return Err("encrypt needs key".into());
    }
    let file = File::open(input).map_err(|e| e.to_string())?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();

    let hash = if check {
        eprint!("bbx: hashing BLAKE3… ");
        let _ = io::stderr().flush();
        let h = hash_file(input)?;
        eprintln!("ok");
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
    write_u32(&mut ctrl, flags)?;
    write_u64(&mut ctrl, size)?;
    write_u32(&mut ctrl, streams as u32)?;
    if let Some(h) = hash {
        ctrl.write_all(&h).map_err(|e| e.to_string())?;
    }

    let ranges = split_ranges(size, streams);
    let sent = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();
    let file = Arc::new(file);
    let key = key.map(Arc::new);

    if progress > 0 {
        let sent_p = Arc::clone(&sent);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(progress.max(1)));
            let n = sent_p.load(Ordering::Relaxed);
            eprint_progress(n, size, t0);
            if n >= size {
                break;
            }
        });
    }

    let mut handles = Vec::new();
    for (i, mut sock) in conns.into_iter().enumerate() {
        let (start, end) = ranges[i];
        let f = Arc::clone(&file);
        let sent_c = Arc::clone(&sent);
        let k = key.clone();
        handles.push(thread::spawn(move || -> Result<(), String> {
            send_range(&mut sock, &f, start, end, i as u32, k.as_deref(), &sent_c)
        }));
    }
    for h in handles {
        h.join().map_err(|_| "thread panic".to_string())??;
    }
    eprint_progress(size, size, t0);
    let elapsed = t0.elapsed().as_secs_f64().max(0.001);
    eprintln!(
        "\nbbx: done {} bytes in {:.2}s ({:.1} MB/s){}",
        size,
        elapsed,
        size as f64 / elapsed / 1024.0 / 1024.0,
        if crypt { " [encrypted]" } else { "" }
    );
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
) -> Result<(), String> {
    let mut off = start;
    let mut left = end - start;
    let mut buf = vec![0u8; if key.is_some() { CRYPT_PT } else { CHUNK }];
    let mut counter = 0u64;
    let cipher = key.map(|k| ChaCha20Poly1305::new_from_slice(k).expect("key"));

    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        read_at_full(f, &mut buf[..want], off)?;
        if let Some(ref c) = cipher {
            let nonce = make_nonce(stream_id, counter);
            counter += 1;
            let ct = c
                .encrypt(&nonce, &buf[..want])
                .map_err(|_| "encrypt failed".to_string())?;
            write_u32(sock, ct.len() as u32)?;
            sock.write_all(&ct).map_err(|e| e.to_string())?;
        } else {
            sock.write_all(&buf[..want]).map_err(|e| e.to_string())?;
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
) -> Result<(), String> {
    let mut off = start;
    let mut left = end - start;
    let mut buf = vec![0u8; CHUNK];
    let mut counter = 0u64;
    let cipher = key.map(|k| ChaCha20Poly1305::new_from_slice(k).expect("key"));

    while left > 0 {
        if let Some(ref c) = cipher {
            let clen = read_u32(sock)? as usize;
            if clen > CRYPT_PT + 16 + 64 {
                return Err(format!("bad ciphertext len {clen}"));
            }
            let mut ct = vec![0u8; clen];
            sock.read_exact(&mut ct).map_err(|e| e.to_string())?;
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
            sock.read_exact(&mut buf[..want]).map_err(|e| e.to_string())?;
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

fn tune(s: &TcpStream, wnd: usize) {
    let _ = s.set_nodelay(true);
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
}
