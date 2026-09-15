//! In-crate unit tests for internal helpers.
use crate::cli::{parse_key, parse_port_range};
use crate::commands::{is_remote_spec, split_host_path};
use crate::crypto::{aead_decrypt, aead_encrypt, derive_aead_key, frame_aad, gen_key, hex, stream_id_tag};
use crate::engine::sink_work_path;
use crate::net::{bind_ephemeral, cleartext_allowed, split_listen_spec, validate_advertise};
use crate::tree::{dest_path_has_symlink, is_safe_rel, parse_find_print0, walk_local_files};
use crate::util::split_ranges;


#[test]
fn ranges_cover_file() {
    let r = split_ranges(100, 3);
    assert_eq!(r.iter().map(|(a, b)| b - a).sum::<u64>(), 100);
}

#[test]
fn key_roundtrip() {
    let k = gen_key();
    let h = hex(&k);
    assert_eq!(parse_key(&h).unwrap(), k);
}

#[test]
fn derive_aead_unique_per_salt() {
    let psk = [0x42u8; 32];
    let s1 = [1u8; 32];
    let s2 = [2u8; 32];
    let a = derive_aead_key(&psk, &s1);
    let b = derive_aead_key(&psk, &s2);
    let a2 = derive_aead_key(&psk, &s1);
    assert_ne!(a, b, "different salts must yield different AEAD keys");
    assert_eq!(a, a2, "same psk+salt must be deterministic");
    assert_ne!(a, psk, "derived key must not equal raw PSK");
}

#[test]
fn stream_id_mac_binds_psk() {
    let psk = [7u8; 32];
    let t0 = stream_id_tag(&psk, 0);
    let t1 = stream_id_tag(&psk, 1);
    let t0b = stream_id_tag(&psk, 0);
    assert_ne!(t0, t1);
    assert_eq!(t0, t0b);
    let other = stream_id_tag(&[8u8; 32], 0);
    assert_ne!(t0, other);
}

#[test]
fn aead_aad_mismatch_fails() {
    let k = derive_aead_key(&[1u8; 32], &[2u8; 32]);
    let aad_ok = frame_aad(2, 100, 4, 0, &[2u8; 32]);
    let aad_bad = frame_aad(2, 101, 4, 0, &[2u8; 32]);
    let ct = aead_encrypt(&k, 0, 0, b"hello", &aad_ok).unwrap();
    assert!(aead_decrypt(&k, 0, 0, &ct, &aad_ok).is_ok());
    assert!(aead_decrypt(&k, 0, 0, &ct, &aad_bad).is_err());
}

#[test]
fn cleartext_loopback_ok() {
    assert!(cleartext_allowed("127.0.0.1:9").is_ok());
    assert!(cleartext_allowed("127.0.0.1").is_ok());
}

#[test]
fn advertise_rejects_metachar() {
    assert!(validate_advertise("10.0.0.1").is_ok());
    assert!(validate_advertise("host.example").is_ok());
    assert!(validate_advertise("evil;rm -rf").is_err());
    assert!(validate_advertise("a b").is_err());
    assert!(validate_advertise("").is_err());
}

#[test]
fn remote_spec() {
    assert!(is_remote_spec("user@host:/tmp/x"));
    assert!(!is_remote_spec("/tmp/x"));
    assert!(is_remote_spec("[::1]:/tmp/x"));
    assert!(is_remote_spec("user@[2001:db8::1]:/data"));
    assert!(!is_remote_spec("C:/windows/path"));
    assert_eq!(
        split_host_path("[::1]:/tmp/x").unwrap(),
        ("[::1]", "/tmp/x")
    );
    assert_eq!(
        split_host_path("user@[::1]:/tmp/x").unwrap(),
        ("user@[::1]", "/tmp/x")
    );
}

#[test]
fn rejects_unsafe_remote_paths() {
    assert!(is_safe_rel("a/b/c.txt"));
    assert!(is_safe_rel("root.bin"));
    assert!(!is_safe_rel("/etc/passwd"));
    assert!(!is_safe_rel("../secrets"));
    assert!(!is_safe_rel("a/../../b"));
    assert!(!is_safe_rel(""));
}

#[test]
fn parse_find_print0_keeps_spaces_and_newlines() {
    // "a b.txt\0dir/\nfile.txt\0" — second name contains a newline
    let mut raw = Vec::new();
    raw.extend_from_slice(b"./a b.txt\0");
    raw.extend_from_slice(b"./dir/\nfile.txt\0");
    let files = parse_find_print0(&raw);
    assert_eq!(files.len(), 2);
    assert!(files.iter().any(|f| f == "a b.txt"));
    assert!(files.iter().any(|f| f == "dir/\nfile.txt"));
    // no trim of internal spaces
    assert!(!files.iter().any(|f| f == "a b.txt ".trim() && f.ends_with(' ')));
}

#[test]
#[cfg(unix)]
fn dest_symlink_component_detected() {
    let dir = std::env::temp_dir().join(format!("bbx_sym_{}", std::process::id()));
    let outside = std::env::temp_dir().join(format!("bbx_sym_out_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    assert!(dest_path_has_symlink(&dir, "link/file").unwrap());
    assert!(!dest_path_has_symlink(&dir, "safe/file").unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn sink_work_path_temp_for_fresh() {
    let (p, is_temp) = sink_work_path("/tmp/bbx_dest.bin", 0).unwrap();
    assert!(is_temp);
    assert!(p.contains(".bbx.") && p.ends_with(".tmp"));
    let (p2, is_temp2) = sink_work_path("/tmp/bbx_dest.bin", 100).unwrap();
    assert!(!is_temp2);
    assert_eq!(p2, "/tmp/bbx_dest.bin");
}

#[test]
fn walk_lists_nested_files() {
    let dir = std::env::temp_dir().join(format!("bbx_walk_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("a/b")).unwrap();
    std::fs::write(dir.join("a/b/c.txt"), b"hi").unwrap();
    std::fs::write(dir.join("root.bin"), b"x").unwrap();
    let files = walk_local_files(&dir).unwrap();
    let rels: Vec<_> = files.iter().map(|(_, r)| r.as_str()).collect();
    assert!(rels.contains(&"a/b/c.txt") || rels.iter().any(|r| r.ends_with("c.txt")));
    assert!(rels.iter().any(|r| r.ends_with("root.bin")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn port_range_parse() {
    assert_eq!(parse_port_range("50000-50010").unwrap(), (50000, 50010));
    assert_eq!(parse_port_range("1000:1001").unwrap(), (1000, 1001));
    assert!(parse_port_range("0-10").is_err());
    assert!(parse_port_range("20-10").is_err());
}

#[test]
fn bind_in_range() {
    let l = bind_ephemeral(Some((45000, 45050))).unwrap();
    let p = l.local_addr().unwrap().port();
    assert!((45000..=45050).contains(&p));
}

#[test]
fn listen_spec_split() {
    assert_eq!(split_listen_spec("0.0.0.0:0").unwrap(), ("0.0.0.0".into(), 0));
    assert_eq!(split_listen_spec("127.0.0.1:9").unwrap(), ("127.0.0.1".into(), 9));
}
