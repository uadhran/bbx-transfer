//! Regression for the encrypted recursive (`-r` + `-e`) path.
//!
//! `cp -r` runs one BBX2 session per file (README/ROADMAP), and the historical
//! failure recorded in REPORT.md was "tiny5k bbx enc push FAIL — decrypt/corrupt
//! errors mid-tree": the *per-file encrypted transfers* corrupted, not the SSH
//! orchestration around them. SSH-to-localhost is not reliably available in CI,
//! so this test drives that failing unit directly over loopback — the same
//! encrypted sink/source sessions the tree performs for each file — across the
//! sizes that actually stress it: empty, tiny (single-stream, as the tree picks
//! for files ≤ 1 MiB), and the 64 KiB ChaCha20-Poly1305 frame boundary. It runs
//! with `-e -c` (encrypt + BLAKE3), which is exactly the `cp` default, so the
//! sink independently verifies each file's hash after write.

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

/// Cheap deterministic pseudo-random content so failures are reproducible.
fn fill(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push((x & 0xff) as u8);
    }
    v
}

/// One encrypted BBX2 file session over loopback: the unit `cp -r -e` repeats per file.
fn encrypt_roundtrip(streams: &str, key_hex: &str, src: &std::path::Path, dest: &std::path::Path) {
    let mut sink = Command::new(bbx())
        .args([
            "sink",
            "-l",
            "127.0.0.1:0",
            "-o",
            dest.to_str().unwrap(),
            "-s",
            streams,
            "-e",
            "-c",
            "-k",
            key_hex,
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
            streams,
            "-e",
            "-c",
            "-k",
            key_hex,
        ])
        .stderr(Stdio::null())
        .status()
        .unwrap();
    let sink_st = sink.wait().unwrap();
    assert!(
        src_st.success() && sink_st.success(),
        "encrypted transfer failed (streams={streams}) for {}",
        src.display()
    );
    assert_eq!(
        std::fs::read(src).unwrap(),
        std::fs::read(dest).unwrap(),
        "encrypted content mismatch (streams={streams}) for {}",
        src.display()
    );
}

#[test]
fn encrypted_tree_files_roundtrip() {
    let dir = std::env::temp_dir().join(format!("bbx_it_tree_enc_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = [0x5Au8; 32];
    let key_hex = hex32(&key);

    // Boundary and tiny sizes that historically corrupted mid-tree, plus a spread
    // of small files to emulate the tiny5k workload. 64 KiB == CRYPT_PT frame edge.
    let mut sizes: Vec<usize> = vec![0, 1, 2, 100, 1023, 1024, 1025, 65_535, 65_536, 65_537, 100_000];
    for i in 0..40 {
        sizes.push(((i * 811) % 4096) + 1);
    }

    for (i, &len) in sizes.iter().enumerate() {
        let src = dir.join(format!("src_{i}_{len}.bin"));
        let dest = dir.join(format!("dst_{i}_{len}.bin"));
        std::fs::write(&src, fill(i as u64 + 1, len)).unwrap();
        // Tree mode uses a single stream for files ≤ 1 MiB; all files here qualify.
        encrypt_roundtrip("1", &key_hex, &src, &dest);
    }

    // Also exercise the multi-stream encrypted path on small files (streams that
    // split the file into several encrypted ranges, incl. an empty tail range).
    for (i, &len) in [0usize, 7, 65_536, 100_000].iter().enumerate() {
        let src = dir.join(format!("ms_src_{i}.bin"));
        let dest = dir.join(format!("ms_dst_{i}.bin"));
        std::fs::write(&src, fill(1000 + i as u64, len)).unwrap();
        encrypt_roundtrip("4", &key_hex, &src, &dest);
    }

    let _ = std::fs::remove_dir_all(&dir);
}
