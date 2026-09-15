//! SSH bootstrap: remote command quoting, agent spawn, banner parsing, agent lifecycle.

use crate::cli::parse_key;
use crate::net::io_timeout;
use std::env;
use std::io::{self, Read};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Quote a path/arg for remote `sh` via ssh.
/// Leading `~/` becomes `"$HOME/..."` so tilde expands (single-quoted `~` does not).
pub(crate) fn shell_quote(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/") {
        format!("\"$HOME/{}\"", shell_escape_dq(rest))
    } else if s == "~" {
        "\"$HOME\"".into()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

pub(crate) fn shell_escape_dq(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
}

pub(crate) fn remote_bin() -> String {
    env::var("BBX_REMOTE").unwrap_or_else(|_| "bbx".into())
}

pub(crate) fn ce_flags(check: bool, crypt: bool) -> String {
    format!(
        "{} {}",
        if check { "-c" } else { "-C" },
        if crypt { "-e" } else { "-E" }
    )
}

pub(crate) fn resume_flag(resume: bool) -> &'static str {
    if resume { " -A" } else { "" }
}

/// Prefer transfer error; kill agent on failure; surface non-zero agent exit if transfer OK.
/// Bounded wait so a stuck remote agent cannot hang the local process forever.
pub(crate) fn finish_agent(child: &mut Child, transfer: Result<(), String>, role: &str) -> Result<(), String> {
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

pub(crate) fn agent_wait_timeout() -> Duration {
    env::var("BBX_AGENT_WAIT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(io_timeout)
}

pub(crate) fn ssh_spawn(remote: &str, remote_cmd: &str) -> Result<Child, String> {
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
pub(crate) fn ssh_start_banner(
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
