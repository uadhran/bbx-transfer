//! SSH bootstrap: remote command quoting, agent spawn, banner parsing, agent lifecycle.

use crate::cli::parse_key;
use crate::crypto::hex;
use crate::net::io_timeout;
use std::env;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Substring an old agent prints when it rejects `--key-stdin`.
pub(crate) const OLD_AGENT_MARK: &[u8] = b"unknown flag --key-stdin";
pub(crate) const OLD_AGENT_MSG: &str =
    "remote bbx does not support --key-stdin; upgrade the remote to 1.1.0";
/// After the ssh child has exited, stop relaying stderr even if the pipe stays open
/// (ControlMaster / ControlPersist can keep the write end alive).
pub(crate) const STDERR_RELAY_DRAIN: Duration = Duration::from_millis(200);
const STDERR_TAIL: usize = 4096;
const RELAY_POLL_MS: libc::c_int = 50;

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
pub(crate) fn finish_agent(
    agent: &mut SshAgent,
    transfer: Result<(), String>,
    role: &str,
) -> Result<(), String> {
    if transfer.is_err() {
        let _ = agent.child.kill();
    }
    let limit = agent_wait_timeout();
    let deadline = Instant::now() + limit;
    let st = loop {
        match agent.child.try_wait() {
            Ok(Some(s)) => break Ok(s),
            Ok(None) if Instant::now() >= deadline => {
                let _ = agent.child.kill();
                let _ = agent.child.wait();
                break Err(format!(
                    "{role} wait timed out after {}s",
                    limit.as_secs()
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(e) => break Err(format!("{role} wait: {e}")),
        }
    };
    agent.shutdown_relay();
    if agent.saw_old_agent() {
        return Err(OLD_AGENT_MSG.into());
    }
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

/// Remember `OLD_AGENT_MARK` across reads. A match may be split on any byte boundary.
pub(crate) fn feed_stderr_scan(carry: &mut Vec<u8>, chunk: &[u8], saw: &AtomicBool) {
    if saw.load(Ordering::Relaxed) || chunk.is_empty() {
        return;
    }
    carry.extend_from_slice(chunk);
    if carry.windows(OLD_AGENT_MARK.len()).any(|w| w == OLD_AGENT_MARK) {
        saw.store(true, Ordering::Relaxed);
        carry.clear();
        return;
    }
    let keep = OLD_AGENT_MARK.len() - 1;
    if carry.len() > keep {
        let drop_n = carry.len() - keep;
        carry.drain(..drop_n);
    }
}

fn push_tail(tail: &Mutex<Vec<u8>>, chunk: &[u8]) {
    let mut buf = tail.lock().unwrap_or_else(|e| e.into_inner());
    buf.extend_from_slice(chunk);
    if buf.len() > STDERR_TAIL {
        let drop_n = buf.len() - STDERR_TAIL;
        buf.drain(..drop_n);
    }
}

/// Copy ssh stderr to this process as raw bytes, flushing each read.
/// `child_done` makes the loop stop after `STDERR_RELAY_DRAIN` even if the pipe stays open.
pub(crate) fn relay_stderr<R: Read + AsRawFd>(
    mut stderr: R,
    saw: Arc<AtomicBool>,
    child_done: Arc<AtomicBool>,
    tail: Arc<Mutex<Vec<u8>>>,
) {
    let fd = stderr.as_raw_fd();
    let mut carry = Vec::new();
    let mut buf = [0u8; 1024];
    let mut drain_at: Option<Instant> = None;
    loop {
        if child_done.load(Ordering::Relaxed) && drain_at.is_none() {
            drain_at = Some(Instant::now() + STDERR_RELAY_DRAIN);
        }
        let wait_ms = if let Some(deadline) = drain_at {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            left.as_millis().min(RELAY_POLL_MS as u128) as libc::c_int
        } else {
            RELAY_POLL_MS
        };
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, wait_ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if rc == 0 {
            continue;
        }
        if pfd.revents & libc::POLLIN == 0 {
            break;
        }
        match stderr.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let chunk = &buf[..n];
                let mut out = io::stderr();
                let _ = out.write_all(chunk);
                let _ = out.flush();
                push_tail(&tail, chunk);
                feed_stderr_scan(&mut carry, chunk, &saw);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

pub(crate) struct SshAgent {
    pub child: Child,
    relay: Option<thread::JoinHandle<()>>,
    child_done: Arc<AtomicBool>,
    relay_done: Arc<AtomicBool>,
    saw_old: Arc<AtomicBool>,
    tail: Arc<Mutex<Vec<u8>>>,
}

/// Sets `relay_done` when the relay thread returns, including on panic.
struct RelayFinished(Arc<AtomicBool>);

impl Drop for RelayFinished {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Wait until the relay finishes or `STDERR_RELAY_DRAIN` elapses, then join.
/// A thread still blocked (for example on our own stderr) is detached so process
/// exit does not sit in the join.
pub(crate) fn release_relay(relay: &mut Option<thread::JoinHandle<()>>, done: &AtomicBool) {
    let deadline = Instant::now() + STDERR_RELAY_DRAIN;
    while !done.load(Ordering::Relaxed) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        thread::sleep(Duration::from_millis(10).min(left));
    }
    if let Some(thr) = relay.take() {
        if done.load(Ordering::Relaxed) {
            let _ = thr.join();
        }
    }
}

impl SshAgent {
    pub(crate) fn start(mut child: Child, stderr: impl Read + AsRawFd + Send + 'static) -> Self {
        let child_done = Arc::new(AtomicBool::new(false));
        let relay_done = Arc::new(AtomicBool::new(false));
        let saw_old = Arc::new(AtomicBool::new(false));
        let tail = Arc::new(Mutex::new(Vec::new()));
        let relay = thread::spawn({
            let child_done = Arc::clone(&child_done);
            let relay_done = Arc::clone(&relay_done);
            let saw_old = Arc::clone(&saw_old);
            let tail = Arc::clone(&tail);
            move || {
                let _finished = RelayFinished(relay_done);
                relay_stderr(stderr, saw_old, child_done, tail);
            }
        });
        // stderr was moved into the thread; the Child must not also own it.
        let _ = child.stderr.take();
        Self {
            child,
            relay: Some(relay),
            child_done,
            relay_done,
            saw_old,
            tail,
        }
    }

    pub(crate) fn saw_old_agent(&self) -> bool {
        self.saw_old.load(Ordering::Relaxed)
    }

    fn stderr_text(&self) -> String {
        let buf = self.tail.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&buf).trim().to_string()
    }

    /// Unblock the relay. Join it if it finishes within `STDERR_RELAY_DRAIN`.
    /// Otherwise detach so a blocked write to our stderr cannot hold exit.
    pub(crate) fn shutdown_relay(&mut self) {
        self.child_done.store(true, Ordering::Relaxed);
        release_relay(&mut self.relay, &self.relay_done);
    }

    /// Write one hex line and close ssh stdin. A closed pipe is reported with the
    /// ssh status and the stderr already printed, never as a bare broken-pipe error.
    pub(crate) fn write_key(&mut self, key: &[u8; 32]) -> Result<(), String> {
        let mut stdin = self.child.stdin.take().ok_or("ssh stdin")?;
        let line = format!("{}\n", hex(key));
        if stdin.write_all(line.as_bytes()).is_err() {
            drop(stdin);
            self.shutdown_relay();
            let status = match self.child.try_wait() {
                Ok(Some(st)) => st.to_string(),
                Ok(None) => {
                    let _ = self.child.kill();
                    match self.child.wait() {
                        Ok(st) => st.to_string(),
                        Err(e) => format!("wait: {e}"),
                    }
                }
                Err(e) => format!("wait: {e}"),
            };
            let printed = self.stderr_text();
            return Err(if printed.is_empty() {
                format!("ssh exited {status} before the session key was sent")
            } else {
                format!("ssh exited {status} before the session key was sent: {printed}")
            });
        }
        drop(stdin);
        Ok(())
    }
}

impl Drop for SshAgent {
    fn drop(&mut self) {
        self.shutdown_relay();
    }
}

fn ssh_agent(
    remote: &str,
    remote_cmd: &str,
    key: Option<&[u8; 32]>,
    pipe_stdout: bool,
) -> Result<SshAgent, String> {
    let mut cmd = Command::new("ssh");
    cmd.arg(remote).arg(remote_cmd);
    cmd.stdin(if key.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    cmd.stdout(if pipe_stdout {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("ssh: {e}"))?;
    let stderr = child.stderr.take().ok_or("ssh stderr")?;
    let mut agent = SshAgent::start(child, stderr);
    if let Some(k) = key {
        agent.write_key(k)?;
    }
    Ok(agent)
}

pub(crate) fn ssh_spawn(
    remote: &str,
    remote_cmd: &str,
    key: Option<&[u8; 32]>,
) -> Result<SshAgent, String> {
    ssh_agent(remote, remote_cmd, key, false)
}

/// Read PORT, optional KEY, optional RESUME from remote agent stdout.
pub(crate) fn ssh_start_banner(
    remote: &str,
    remote_cmd: &str,
    expect_key: bool,
    expect_resume: bool,
    key: Option<&[u8; 32]>,
) -> Result<(SshAgent, u16, Option<[u8; 32]>, u64), String> {
    let mut agent = ssh_agent(remote, remote_cmd, key, true)?;
    let mut stdout = agent.child.stdout.take().ok_or("ssh stdout")?;
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
    let port = match port {
        Some(p) => p,
        None => return Err(banner_fail(&mut agent, format!("remote did not print PORT: {s:?}"))),
    };
    if expect_key && key.is_none() {
        return Err(banner_fail(
            &mut agent,
            format!("remote did not print KEY (upgrade remote bbx?): {s:?}"),
        ));
    }
    Ok((agent, port, key, resume_from))
}

fn banner_fail(agent: &mut SshAgent, msg: String) -> String {
    agent.shutdown_relay();
    let msg = if agent.saw_old_agent() {
        OLD_AGENT_MSG.to_string()
    } else {
        msg
    };
    let _ = agent.child.kill();
    let _ = agent.child.wait();
    msg
}
