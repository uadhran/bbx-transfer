//! bbx — multi-stream bulk copy (bbcp ideas, new protocol BBX2).
//!
//!   bbx sink   -l ADDR -o FILE | -a ADDR -o FILE   [-s N] [-w B] [-c]
//!   bbx source -a ADDR -i FILE | -l ADDR -i FILE   [-s N] [-w B] [-c] [-P SEC]
//!   bbx cp [-s N] [-w B] [-P SEC] [-c|-C] [-z] SRC DEST
//!
//! Direction: local↔remote via ssh. -z reverse (listener on the side that has
//! the file / accepts outbound-only peers). See SPEC.md.

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
const FLAG_BLAKE3: u32 = 1;

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
         bbx sink   (-l ADDR | -a ADDR) -o FILE [-s N] [-w BYTES] [-c]\n\
         bbx source (-a ADDR | -l ADDR) -i FILE [-s N] [-w BYTES] [-c] [-P SEC]\n\
         bbx cp [-s N] [-w BYTES] [-P SEC] [-c|-C] [-z] SRC DEST\n\n\
         cp: local→remote (push) or remote→local (pull). One side must be host:path.\n\
         -c verify BLAKE3 (default on for cp). -C skip verify.\n\
         -z reverse: peer dials the side that holds/listens the data (NAT-friendly push).\n\
         BBX_REMOTE=path  remote bbx binary (default: bbx)\n"
    );
    std::process::exit(code);
}

// --- flags -----------------------------------------------------------------

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

fn shell_quote(s: &str) -> String {
    // safe for remote sh -c single-quoted strings
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

fn remote_bin() -> String {
    env::var("BBX_REMOTE").unwrap_or_else(|_| "bbx".into())
}

// --- commands --------------------------------------------------------------

fn cmd_sink(args: &[String]) -> Result<(), String> {
    let f = parse_flags(args)?;
    let out = f.output.ok_or("sink needs -o FILE")?;
    match (&f.listen, &f.addr) {
        (Some(l), None) => run_sink_listen(l, &out, f.streams, f.wnd, f.check),
        (None, Some(a)) => run_sink_connect(a, &out, f.streams, f.wnd, f.check),
        _ => Err("sink needs exactly one of -l ADDR or -a ADDR".into()),
    }
}

fn cmd_source(args: &[String]) -> Result<(), String> {
    let f = parse_flags(args)?;
    let input = f.input.ok_or("source needs -i FILE")?;
    match (&f.listen, &f.addr) {
        (None, Some(a)) => run_source_connect(a, &input, f.streams, f.wnd, f.progress, f.check),
        (Some(l), None) => run_source_listen(l, &input, f.streams, f.wnd, f.progress, f.check),
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
    let check = if f.check_set { f.check } else { true }; // default on
    let bin = remote_bin();
    let s = f.streams;
    let w = f.wnd;
    let p = f.progress;
    let rev = f.reverse;

    let src_remote = is_remote_spec(src);
    let dst_remote = is_remote_spec(dest);
    match (src_remote, dst_remote) {
        (false, true) => {
            // push local → remote
            let (remote, rpath) = split_host_path(dest)?;
            if rev {
                cp_push_reverse(&bin, remote, rpath, src, s, w, p, check)
            } else {
                cp_push_forward(&bin, remote, rpath, src, s, w, p, check)
            }
        }
        (true, false) => {
            // pull remote → local
            let (remote, rpath) = split_host_path(src)?;
            if rev {
                cp_pull_reverse(&bin, remote, rpath, dest, s, w, p, check)
            } else {
                cp_pull_forward(&bin, remote, rpath, dest, s, w, p, check)
            }
        }
        (false, false) => Err("cp needs one remote host:path side".into()),
        (true, true) => Err("remote→remote not supported (pull then push)".into()),
    }
}

fn is_remote_spec(s: &str) -> bool {
    // user@host:path or host:path — not absolute local /x or bare relative
    if s.starts_with('/') || s.starts_with("./") || s.starts_with("../") {
        return false;
    }
    match s.rfind(':') {
        None => false,
        Some(i) => {
            let host = &s[..i];
            !host.is_empty() && !host.contains('/') // avoid Windows-ish C:\
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

/// Remote listens as sink; local source connects (needs inbound TCP to remote).
fn cp_push_forward(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_src: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
) -> Result<(), String> {
    let c = if check { "-c" } else { "-C" };
    let cmd = format!(
        "{} sink -l 0.0.0.0:0 -o {} -s {streams} -w {wnd} {c}",
        shell_quote(bin),
        shell_quote(rpath)
    );
    let (mut child, port) = ssh_start_port(remote, &cmd)?;
    let host = host_only(remote);
    let addr = format!("{host}:{port}");
    eprintln!("bbx: push {local_src} → {remote}:{rpath} via {addr} streams={streams} check={check}");
    let r = run_source_connect(&addr, local_src, streams, wnd, progress, check);
    let _ = child.wait();
    r
}

/// Local source listens; remote sink connects out (remote needs to reach local).
fn cp_push_reverse(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_src: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
) -> Result<(), String> {
    let cflag = check;
    // bind source listener
    let listener = TcpListener::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    let port = local.port();
    // discover local IP the remote can use: BBX_ADVERTISE or guess from ssh path
    let advertise = env::var("BBX_ADVERTISE").unwrap_or_else(|_| guess_local_ip().unwrap_or_else(|| "127.0.0.1".into()));
    let addr = format!("{advertise}:{port}");
    let c = if check { "-c" } else { "-C" };
    let cmd = format!(
        "{} sink -a {} -o {} -s {streams} -w {wnd} {c}",
        shell_quote(bin),
        shell_quote(&addr),
        shell_quote(rpath)
    );
    eprintln!("bbx: push -z {local_src} → {remote}:{rpath} (remote dials {addr}) streams={streams}");
    let mut child = ssh_spawn(remote, &cmd)?;
    // give ssh a moment to auth before we accept; sink will connect when ready
    let r = run_source_with_listener(listener, local_src, streams, wnd, progress, cflag);
    let _ = child.wait();
    r
}

/// Local sink listens; remote source connects (local must be reachable from remote).
fn cp_pull_forward(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_dst: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
) -> Result<(), String> {
    let listener = TcpListener::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let advertise = env::var("BBX_ADVERTISE").unwrap_or_else(|_| guess_local_ip().unwrap_or_else(|| "127.0.0.1".into()));
    let addr = format!("{advertise}:{port}");
    let c = if check { "-c" } else { "-C" };
    let cmd = format!(
        "{} source -a {} -i {} -s {streams} -w {wnd} {c}",
        shell_quote(bin),
        shell_quote(&addr),
        shell_quote(rpath)
    );
    eprintln!("bbx: pull {remote}:{rpath} → {local_dst} (remote dials {addr}) streams={streams}");
    let mut child = ssh_spawn(remote, &cmd)?;
    let r = run_sink_with_listener(listener, local_dst, streams, wnd, check, progress);
    let _ = child.wait();
    r
}

/// Remote source listens; local sink connects (needs inbound TCP to remote).
fn cp_pull_reverse(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_dst: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
) -> Result<(), String> {
    let c = if check { "-c" } else { "-C" };
    let cmd = format!(
        "{} source -l 0.0.0.0:0 -i {} -s {streams} -w {wnd} {c}",
        shell_quote(bin),
        shell_quote(rpath)
    );
    let (mut child, port) = ssh_start_port(remote, &cmd)?;
    let host = host_only(remote);
    let addr = format!("{host}:{port}");
    eprintln!("bbx: pull -z {remote}:{rpath} → {local_dst} via {addr} streams={streams}");
    let r = run_sink_connect(&addr, local_dst, streams, wnd, check);
    let _ = progress; // sink connect has no progress yet; pull local is receive
    let _ = child.wait();
    r
}

fn host_only(remote: &str) -> &str {
    remote.rsplit('@').next().unwrap_or(remote)
}

fn guess_local_ip() -> Option<String> {
    // UDP connect trick — no packets sent
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    Some(s.local_addr().ok()?.ip().to_string())
}

// --- ssh helpers -----------------------------------------------------------

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

fn ssh_start_port(remote: &str, remote_cmd: &str) -> Result<(Child, u16), String> {
    let mut child = Command::new("ssh")
        .arg(remote)
        .arg(remote_cmd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("ssh: {e}"))?;

    let mut stdout = child.stdout.take().ok_or("ssh stdout")?;
    let mut line = Vec::new();
    let mut buf = [0u8; 128];
    loop {
        let n = stdout.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        line.extend_from_slice(&buf[..n]);
        if line.contains(&b'\n') {
            break;
        }
        if line.len() > 256 {
            break;
        }
    }
    // keep draining stdout so remote isn't blocked
    thread::spawn(move || {
        let mut sink = io::sink();
        let _ = io::copy(&mut stdout, &mut sink);
    });

    let s = String::from_utf8_lossy(&line);
    let port: u16 = s
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("remote did not print PORT: {s:?}"))?
        .parse()
        .map_err(|_| format!("bad PORT line: {s:?}"))?;
    Ok((child, port))
}

// --- transfer engine -------------------------------------------------------

fn run_sink_listen(
    listen: &str,
    out: &str,
    streams: usize,
    wnd: usize,
    check: bool,
) -> Result<(), String> {
    let listener = TcpListener::bind(listen).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    println!("PORT {port}");
    let _ = io::stdout().flush();
    run_sink_with_listener(listener, out, streams, wnd, check, 0)
}

fn run_sink_connect(
    addr: &str,
    out: &str,
    streams: usize,
    wnd: usize,
    check: bool,
) -> Result<(), String> {
    let dest: SocketAddr = addr.parse::<SocketAddr>().map_err(|e| e.to_string())?;
    // connect N streams; first is control
    let mut conns = Vec::with_capacity(streams);
    for i in 0..streams {
        let s = TcpStream::connect(dest).map_err(|e| format!("sink connect[{i}]: {e}"))?;
        tune(&s, wnd);
        conns.push(s);
    }
    finish_sink(conns, out, streams, check, 0)
}

fn run_sink_with_listener(
    listener: TcpListener,
    out: &str,
    streams: usize,
    wnd: usize,
    check: bool,
    progress: u64,
) -> Result<(), String> {
    let mut conns = Vec::with_capacity(streams);
    for i in 0..streams {
        let (s, _) = listener
            .accept()
            .map_err(|e| format!("sink accept[{i}]: {e}"))?;
        tune(&s, wnd);
        conns.push(s);
    }
    finish_sink(conns, out, streams, check, progress)
}

fn finish_sink(
    mut conns: Vec<TcpStream>,
    out: &str,
    streams_hint: usize,
    check: bool,
    progress: u64,
) -> Result<(), String> {
    let mut ctrl = conns.remove(0);
    let mut magic = [0u8; 4];
    ctrl.read_exact(&mut magic).map_err(|e| e.to_string())?;
    if &magic != MAGIC {
        return Err(format!("bad magic {:?}", magic));
    }
    let flags = read_u32(&mut ctrl)?;
    let size = read_u64(&mut ctrl)?;
    let n = read_u32(&mut ctrl)? as usize;
    if n == 0 || n > 64 {
        return Err("bad stream count".into());
    }
    let want_check = flags & FLAG_BLAKE3 != 0;
    if want_check != check {
        // peer wins for wire; local -c should match
    }
    let streams = n;
    if streams_hint != 0 && streams_hint != streams {
        return Err(format!(
            "stream count mismatch: local -s {streams_hint}, peer {streams}"
        ));
    }
    // conns already holds the remaining streams-1 sockets (stream 0 is ctrl)
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
        handles.push(thread::spawn(move || -> Result<(), String> {
            let mut off = start;
            let mut left = end - start;
            let mut buf = vec![0u8; CHUNK];
            while left > 0 {
                let want = left.min(buf.len() as u64) as usize;
                sock.read_exact(&mut buf[..want]).map_err(|e| e.to_string())?;
                write_at_full(&f, &buf[..want], off)?;
                g.fetch_add(want as u64, Ordering::Relaxed);
                off += want as u64;
                left -= want as u64;
            }
            Ok(())
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
) -> Result<(), String> {
    let dest: SocketAddr = addr.parse::<SocketAddr>().map_err(|e| e.to_string())?;
    let mut conns = Vec::with_capacity(streams);
    for i in 0..streams {
        let s = TcpStream::connect(dest).map_err(|e| format!("source connect[{i}]: {e}"))?;
        tune(&s, wnd);
        conns.push(s);
    }
    finish_source(conns, input, streams, progress, check)
}

fn run_source_listen(
    listen: &str,
    input: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
) -> Result<(), String> {
    let listener = TcpListener::bind(listen).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    println!("PORT {port}");
    let _ = io::stdout().flush();
    run_source_with_listener(listener, input, streams, wnd, progress, check)
}

fn run_source_with_listener(
    listener: TcpListener,
    input: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
) -> Result<(), String> {
    let mut conns = Vec::with_capacity(streams);
    for i in 0..streams {
        let (s, _) = listener
            .accept()
            .map_err(|e| format!("source accept[{i}]: {e}"))?;
        tune(&s, wnd);
        conns.push(s);
    }
    finish_source(conns, input, streams, progress, check)
}

fn finish_source(
    mut conns: Vec<TcpStream>,
    input: &str,
    streams: usize,
    progress: u64,
    check: bool,
) -> Result<(), String> {
    if conns.len() != streams {
        return Err(format!("expected {streams} streams, got {}", conns.len()));
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
    let flags = if check { FLAG_BLAKE3 } else { 0 };
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
        handles.push(thread::spawn(move || -> Result<(), String> {
            let mut off = start;
            let mut left = end - start;
            let mut buf = vec![0u8; CHUNK];
            while left > 0 {
                let want = left.min(buf.len() as u64) as usize;
                read_at_full(&f, &mut buf[..want], off)?;
                sock.write_all(&buf[..want]).map_err(|e| e.to_string())?;
                sent_c.fetch_add(want as u64, Ordering::Relaxed);
                off += want as u64;
                left -= want as u64;
            }
            Ok(())
        }));
    }
    for h in handles {
        h.join().map_err(|_| "thread panic".to_string())??;
    }
    eprint_progress(size, size, t0);
    let elapsed = t0.elapsed().as_secs_f64().max(0.001);
    eprintln!(
        "\nbbx: done {} bytes in {:.2}s ({:.1} MB/s)",
        size,
        elapsed,
        size as f64 / elapsed / 1024.0 / 1024.0
    );
    Ok(())
}

// --- blake3 / util ---------------------------------------------------------

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
fn write_u64(w: &mut impl Write, v: u64) -> Result<(), String> {
    w.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}
fn write_u32(w: &mut impl Write, v: u32) -> Result<(), String> {
    w.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_cover_file() {
        let r = split_ranges(100, 3);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].0, 0);
        assert_eq!(r[2].1, 100);
        assert_eq!(r.iter().map(|(a, b)| b - a).sum::<u64>(), 100);
    }

    #[test]
    fn remote_spec() {
        assert!(is_remote_spec("user@host:/tmp/x"));
        assert!(is_remote_spec("172.18.0.144:~/f"));
        assert!(!is_remote_spec("/tmp/x"));
        assert!(!is_remote_spec("./x"));
    }
}
