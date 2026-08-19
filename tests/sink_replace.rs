//! Finding 1: failed fresh transfer must not destroy a pre-existing destination.
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
fn failed_crypt_overwrite_keeps_old_dest() {
    let dir = std::env::temp_dir().join(format!("bbx_it_repl_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("in.bin");
    let dest = dir.join("out.bin");
    std::fs::write(&src, vec![0xABu8; 50_000]).unwrap();
    let old = b"DO_NOT_DESTROY_ME_EXISTING_DEST";
    std::fs::write(&dest, old).unwrap();

    let key = [0x11u8; 32];
    let wrong = [0x22u8; 32];
    let key_hex = hex32(&key);
    let wrong_hex = hex32(&wrong);

    let mut sink = Command::new(bbx())
        .args([
            "sink",
            "-l",
            "127.0.0.1:0",
            "-o",
            dest.to_str().unwrap(),
            "-s",
            "2",
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
            "2",
            "-e",
            "-C",
            "-k",
            &wrong_hex,
        ])
        .status()
        .unwrap();
    let sink_st = sink.wait().unwrap();
    assert!(!sink_st.success(), "sink must fail on wrong key");

    let kept = std::fs::read(&dest).unwrap();
    assert_eq!(
        kept, old,
        "existing destination must survive failed overwrite"
    );
    // no leftover temp next to dest
    let parent = dir.read_dir().unwrap();
    for e in parent {
        let n = e.unwrap().file_name().to_string_lossy().into_owned();
        assert!(
            !n.contains(".bbx.") || !n.ends_with(".tmp"),
            "temp file left behind: {n}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn successful_overwrite_replaces_dest() {
    let dir = std::env::temp_dir().join(format!("bbx_it_repl_ok_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("in.bin");
    let dest = dir.join("out.bin");
    let payload = vec![0xCDu8; 40_000];
    std::fs::write(&src, &payload).unwrap();
    std::fs::write(&dest, b"old").unwrap();

    let key = [0x33u8; 32];
    let key_hex = hex32(&key);

    let mut sink = Command::new(bbx())
        .args([
            "sink",
            "-l",
            "127.0.0.1:0",
            "-o",
            dest.to_str().unwrap(),
            "-s",
            "2",
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
            "2",
            "-e",
            "-C",
            "-k",
            &key_hex,
        ])
        .status()
        .unwrap();
    let sink_st = sink.wait().unwrap();
    assert!(src_st.success() && sink_st.success());
    assert_eq!(std::fs::read(&dest).unwrap(), payload);
    let _ = std::fs::remove_dir_all(&dir);
}
