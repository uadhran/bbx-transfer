//! Internals reached from an external test crate — only possible now that the
//! implementation lives in a library (`bbx`) rather than a bin-only `main.rs`.
//! Covers a few pure helpers plus the symlink-skip behavior of the tree walk.

use bbx::cli::{parse_key, parse_port_range};
use bbx::net::host_is_loopback;
use bbx::commands::{is_remote_spec, split_host_path};
use bbx::crypto::{aead_decrypt, aead_encrypt, derive_aead_key, frame_aad};
use bbx::tree::{is_safe_rel, walk_local_files};
use bbx::util::split_ranges;

#[test]
fn ranges_partition_size() {
    for &(size, n) in &[(100u64, 3usize), (0, 4), (1, 1), (7, 8), (1 << 20, 64)] {
        let r = split_ranges(size, n);
        assert_eq!(r.len(), n);
        assert_eq!(r.iter().map(|(a, b)| b - a).sum::<u64>(), size);
        // contiguous, non-overlapping, ascending
        let mut prev = 0;
        for (a, b) in r {
            assert_eq!(a, prev);
            assert!(b >= a);
            prev = b;
        }
    }
}

#[test]
fn key_and_port_parsing() {
    assert!(parse_key(&"ab".repeat(32)).is_ok());
    assert!(parse_key("xyz").is_err());
    assert_eq!(parse_port_range("50000-50010").unwrap(), (50000, 50010));
    assert!(parse_port_range("0-5").is_err());
    assert!(host_is_loopback("127.0.0.1"));
    assert!(!host_is_loopback("10.0.0.1"));
}

#[test]
fn remote_spec_and_split() {
    assert!(is_remote_spec("user@host:/tmp/x"));
    assert!(!is_remote_spec("/tmp/x"));
    assert_eq!(
        split_host_path("user@[::1]:/tmp/x").unwrap(),
        ("user@[::1]", "/tmp/x")
    );
    assert!(is_safe_rel("a/b/c"));
    assert!(!is_safe_rel("../escape"));
}

#[test]
fn aead_roundtrip_and_aad_binding() {
    let k = derive_aead_key(&[1u8; 32], &[2u8; 32]);
    let aad = frame_aad(2, 100, 4, 0, &[2u8; 32]);
    let bad = frame_aad(2, 101, 4, 0, &[2u8; 32]);
    let ct = aead_encrypt(&k, 0, 0, b"payload", &aad).unwrap();
    assert_eq!(aead_decrypt(&k, 0, 0, &ct, &aad).unwrap(), b"payload");
    assert!(aead_decrypt(&k, 0, 0, &ct, &bad).is_err());
}

#[test]
#[cfg(unix)]
fn tree_walk_skips_symlinks() {
    let dir = std::env::temp_dir().join(format!("bbx_it_walk_sym_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("real.bin"), b"a").unwrap();
    std::fs::write(dir.join("sub/nested.bin"), b"b").unwrap();
    // A symlink to a real file must NOT appear in the walk output.
    std::os::unix::fs::symlink(dir.join("real.bin"), dir.join("link.bin")).unwrap();

    let files = walk_local_files(&dir).unwrap();
    let rels: Vec<String> = files.iter().map(|(_, r)| r.clone()).collect();
    assert!(rels.iter().any(|r| r.ends_with("real.bin")));
    assert!(rels.iter().any(|r| r.ends_with("nested.bin")));
    assert!(
        !rels.iter().any(|r| r.ends_with("link.bin")),
        "symlink must be skipped, got {rels:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
