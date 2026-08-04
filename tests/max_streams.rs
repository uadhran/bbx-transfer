//! C1: max streams (64) loopback transfer.
use std::io::Read;
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
    panic!("no PORT: {:?}", String::from_utf8_lossy(&buf));
}

#[test]
fn max_streams_64_cleartext() {
    let dir = std::env::temp_dir().join(format!("bbx_it_s64_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("in.bin");
    let dst = dir.join("out.bin");
    // 64 streams need a file large enough that ranges are non-empty-ish; 128 KiB is fine.
    std::fs::write(&src, vec![0xABu8; 128 * 1024]).unwrap();

    let mut sink = Command::new(bbx())
        .args([
            "sink",
            "-l",
            "127.0.0.1:0",
            "-o",
            dst.to_str().unwrap(),
            "-s",
            "64",
            "-C",
            "-E",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let port = read_port(sink.stdout.as_mut().unwrap());
    let src_st = Command::new(bbx())
        .args([
            "source",
            "-a",
            &format!("127.0.0.1:{port}"),
            "-i",
            src.to_str().unwrap(),
            "-s",
            "64",
            "-C",
            "-E",
        ])
        .status()
        .unwrap();
    let sink_st = sink.wait().unwrap();
    assert!(src_st.success() && sink_st.success(), "s=64 transfer failed");
    assert_eq!(std::fs::read(&src).unwrap(), std::fs::read(&dst).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}
