//! Agent key stays off the process command line. Version flags print the crate version.
use std::io::Write;
use std::process::{Command, Stdio};

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
    let mut child = Command::new(bin())
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
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{hex}\n").as_bytes())
        .unwrap();
    let cmdline = std::fs::read(format!("/proc/{}/cmdline", child.id())).unwrap();
    let text = String::from_utf8_lossy(&cmdline).replace('\0', " ");
    let environ = std::fs::read(format!("/proc/{}/environ", child.id())).unwrap_or_default();
    let env_text = String::from_utf8_lossy(&environ).replace('\0', " ");
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(text.contains("--key-stdin"), "{text}");
    assert!(!text.contains(&hex), "key on argv: {text}");
    assert!(!text.contains("BBX_KEY="), "BBX_KEY on argv: {text}");
    assert!(!env_text.contains(&hex), "key in environ: {env_text}");
    assert!(!env_text.contains("BBX_KEY="), "BBX_KEY in environ: {env_text}");
}
