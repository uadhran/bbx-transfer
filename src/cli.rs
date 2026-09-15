//! CLI parsing: flags, sizes, ports, keys, and shared transfer options.

use crate::{DEFAULT_STREAMS, DEFAULT_WND};
use std::env;

pub fn usage(code: i32) {
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

/// Shared transfer settings threaded through orchestration helpers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TransferOpts {
    pub(crate) streams: usize,
    pub(crate) wnd: usize,
    pub(crate) progress: u64,
    pub(crate) check: bool,
    pub(crate) crypt: bool,
    pub(crate) resume: bool,
    pub(crate) json: bool,
    pub(crate) preserve: bool,
    pub(crate) rate: u64,
}

#[derive(Clone)]
pub(crate) struct Flags {
    pub(crate) listen: Option<String>,
    pub(crate) addr: Option<String>,
    pub(crate) input: Option<String>,
    pub(crate) output: Option<String>,
    pub(crate) streams: usize,
    pub(crate) wnd: usize,
    pub(crate) progress: u64,
    pub(crate) check: bool,
    pub(crate) check_set: bool,
    pub(crate) crypt: bool,
    pub(crate) crypt_set: bool,
    pub(crate) key: Option<[u8; 32]>,
    pub(crate) reverse: bool,
    pub(crate) resume: bool,
    pub(crate) resume_from: u64,
    pub(crate) json: bool,
    pub(crate) recurse: bool,
    /// Inclusive listen port range for firewall-friendly binds (`-Z` / `BBX_PORT_RANGE`).
    pub(crate) port_range: Option<(u16, u16)>,
    /// Preserve mode + mtime (FLAG_PRESERVE on wire).
    pub(crate) preserve: bool,
    /// Max payload bytes/sec (0 = unlimited).
    pub(crate) rate_limit: u64,
    pub(crate) rest: Vec<String>,
}

pub(crate) fn parse_flags(args: &[String]) -> Result<Flags, String> {
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
pub fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
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

pub(crate) fn z_flag(range: Option<(u16, u16)>) -> String {
    match range {
        Some((lo, hi)) => format!(" -Z {lo}-{hi}"),
        None => String::new(),
    }
}

pub(crate) fn need<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str, String> {
    args.get(i)
        .map(|s| s.as_str())
        .ok_or_else(|| format!("{flag} needs a value"))
}

pub(crate) fn parse_size(s: &str) -> Result<usize, String> {
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

pub fn parse_key(s: &str) -> Result<[u8; 32], String> {
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
