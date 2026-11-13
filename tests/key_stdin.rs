//! Agent key stays off the process command line. Version flags print the crate version.
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_bbx")
}

#[test]
fn version_flags_print_crate_version() {
    for flag in ["-V", "--version"] {
        let out = Command::new(bin()).arg(flag).output().unwrap();
        assert!(out.status.success(), "{flag} {out:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(text, format!("bbx {}\n", env!("CARGO_PKG_VERSION")));
    }
}

/// Kills the child if the test returns or panics while it is still running.
struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn child_stderr(child: &mut Child) -> String {
    let mut err = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut err);
    }
    err
}

/// Cmdline of a live agent. An early exit fails with the status and full stderr.
fn wait_for_live_cmdline(child: &mut Child) -> String {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let err = child_stderr(child);
                panic!("agent exited early: {status}\n{err}");
            }
            Ok(None) => {
                if let Ok(raw) = std::fs::read(format!("/proc/{}/cmdline", child.id())) {
                    let text = String::from_utf8_lossy(&raw).replace('\0', " ");
                    if text.contains("source") && text.contains("--key-stdin") {
                        return text;
                    }
                }
            }
            Err(e) => panic!("try_wait: {e}"),
        }
        std::thread::yield_now();
    }
}

#[test]
fn key_stdin_is_not_on_the_agent_command_line() {
    let dir = std::env::temp_dir().join(format!(
        "bbx-key-argv-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("in.bin");
    std::fs::write(&input, b"hello key stdin").unwrap();
    let hex = "ab".repeat(32);
    let child = Command::new(bin())
        .args([
            "source",
            "--key-stdin",
            "-l",
            "127.0.0.1:0",
            "-i",
            input.to_str().unwrap(),
            "-s",
            "1",
            "-C",
            "-e",
        ])
        .env_remove("BBX_KEY")
        .env("BBX_IO_TIMEOUT_SECS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut guard = ChildGuard(Some(child));
    let child = guard.0.as_mut().unwrap();
    let text = wait_for_live_cmdline(child);
    let env_raw = std::fs::read(format!("/proc/{}/environ", child.id())).unwrap_or_else(|e| {
        match child.try_wait() {
            Ok(Some(status)) => {
                let err = child_stderr(child);
                panic!("environ unreadable ({e}); agent exited early: {status}\n{err}");
            }
            _ => panic!("environ unreadable ({e}) while agent is live"),
        }
    });
    let env_text = String::from_utf8_lossy(&env_raw).replace('\0', " ");
    assert!(text.contains("--key-stdin"), "{text}");
    assert!(!text.contains(&hex), "key on argv: {text}");
    assert!(!text.contains("BBX_KEY="), "BBX_KEY on argv: {text}");
    assert!(!env_text.contains(&hex), "key in environ: {env_text}");
    assert!(!env_text.contains("BBX_KEY="), "BBX_KEY in environ: {env_text}");

    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(format!("{hex}\n").as_bytes()).unwrap();
    }
    let status = child.wait().unwrap();
    let err = child_stderr(child);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !status.success(),
        "agent exited {status}\n{err}"
    );
    assert!(
        err.contains("source accept timed out after 1s"),
        "agent exited {status}\n{err}"
    );
    assert!(
        !err.contains("key-stdin:"),
        "agent exited {status}\n{err}"
    );
}
