//! Encrypt loopback: matching keys OK; wrong key fails closed on sink.
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

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn encrypt_match_ok_wrong_key_sink_fails() {
    let dir = std::env::temp_dir().join(format!("bbx_it_crypt_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("in.bin");
    let good = dir.join("ok.bin");
    let bad = dir.join("bad.bin");
    std::fs::write(&src, vec![9u8; 80_000]).unwrap();

    let key = [0x42u8; 32];
    let key_hex = hex32(&key);
    let wrong = hex32(&[0x22u8; 32]);

    // match
    let mut sink = Command::new(bbx())
        .args([
            "sink",
            "-l",
            "127.0.0.1:0",
            "-o",
            good.to_str().unwrap(),
            "-s",
            "4",
            "-e",
            "-C",
            "-k",
            &key_hex,
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
            "4",
            "-e",
            "-C",
            "-k",
            &key_hex,
        ])
        .status()
        .unwrap();
    let sink_st = sink.wait().unwrap();
    assert!(src_st.success() && sink_st.success());
    assert_eq!(std::fs::read(&src).unwrap(), std::fs::read(&good).unwrap());

    // mismatch
    let mut sink = Command::new(bbx())
        .args([
            "sink",
            "-l",
            "127.0.0.1:0",
            "-o",
            bad.to_str().unwrap(),
            "-s",
            "4",
            "-e",
            "-C",
            "-k",
            &key_hex,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let port = read_port(sink.stdout.as_mut().unwrap());
    let _ = Command::new(bbx())
        .args([
            "source",
            "-a",
            &format!("127.0.0.1:{port}"),
            "-i",
            src.to_str().unwrap(),
            "-s",
            "4",
            "-e",
            "-C",
            "-k",
            &wrong,
        ])
        .status()
        .unwrap();
    let sink_st = sink.wait().unwrap();
    assert!(!sink_st.success(), "sink must fail closed on wrong key");
    let _ = std::fs::remove_dir_all(&dir);
}
