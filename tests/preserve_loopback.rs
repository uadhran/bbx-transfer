//! --preserve mode+mtime round-trip on unix.
#![cfg(unix)]
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::{Command, Stdio};

fn bbx() -> &'static str {
    env!("CARGO_BIN_EXE_bbx")
}

fn read_port(stdout: &mut impl Read) -> u16 {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 256];
    for _ in 0..200 {
        let n = stdout.read(&mut tmp).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        let s = String::from_utf8_lossy(&buf);
        if let Some(p) = s.lines().find_map(|l| {
            l.strip_prefix("PORT ")
                .and_then(|p| p.split_whitespace().next())
                .and_then(|p| p.parse().ok())
        }) {
            return p;
        }
        if buf.len() > 2048 {
            break;
        }
    }
    panic!("no PORT");
}

#[test]
fn preserve_mode_mtime() {
    let dir = std::env::temp_dir().join(format!("bbx_it_pres_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("in.bin");
    let dst = dir.join("out.bin");
    std::fs::write(&src, b"preserve-me").unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o640)).unwrap();

    let mut sink = Command::new(bbx())
        .args([
            "sink",
            "-l",
            "127.0.0.1:0",
            "-o",
            dst.to_str().unwrap(),
            "-s",
            "2",
            "-C",
            "-E",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let port = read_port(sink.stdout.as_mut().unwrap());
    let st = Command::new(bbx())
        .args([
            "source",
            "-a",
            &format!("127.0.0.1:{port}"),
            "-i",
            src.to_str().unwrap(),
            "-s",
            "2",
            "-C",
            "-E",
            "--preserve",
        ])
        .status()
        .unwrap();
    assert!(st.success() && sink.wait().unwrap().success());
    let sm = std::fs::metadata(&src).unwrap();
    let dm = std::fs::metadata(&dst).unwrap();
    assert_eq!(sm.mode() & 0o777, dm.mode() & 0o777);
    assert_eq!(sm.mtime(), dm.mtime());
    let _ = std::fs::remove_dir_all(&dir);
}
