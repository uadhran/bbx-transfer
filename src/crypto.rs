//! Cryptographic primitives: key derivation, AEAD frames, BLAKE3 hashing.

use crate::{CHUNK, SID_TAG_LEN};
use crate::cli::parse_key;
use std::env;
use std::fs::File;
use std::io::{Read};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};

pub(crate) fn gen_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).expect("getrandom");
    k
}

/// Derive a one-time AEAD key from OOB PSK + per-transfer salt.
/// Prevents ChaCha20-Poly1305 nonce reuse when the same `-k`/`BBX_KEY` is reused.
pub fn derive_aead_key(psk: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(psk, salt).as_bytes()
}

/// MAC over stream id under OOB PSK (before salt). Prevents unauthenticated accept reordering.
pub(crate) fn stream_id_tag(psk: &[u8; 32], id: u32) -> [u8; SID_TAG_LEN] {
    let mut msg = [0u8; 8];
    msg[0..4].copy_from_slice(b"SID\0");
    msg[4..8].copy_from_slice(&id.to_le_bytes());
    let h = blake3::keyed_hash(psk, &msg);
    let mut tag = [0u8; SID_TAG_LEN];
    tag.copy_from_slice(&h.as_bytes()[..SID_TAG_LEN]);
    tag
}

/// AAD bound into every payload AEAD tag when encrypting.
pub fn frame_aad(flags: u32, size: u64, streams: u32, resume_from: u64, salt: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 8 + 4 + 8 + 32);
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(&streams.to_le_bytes());
    v.extend_from_slice(&resume_from.to_le_bytes());
    v.extend_from_slice(salt);
    v
}

pub fn aead_encrypt(
    key: &[u8; 32],
    stream_id: u32,
    counter: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let c = ChaCha20Poly1305::new_from_slice(key).map_err(|_| "bad key".to_string())?;
    c.encrypt(
        &make_nonce(stream_id, counter),
        Payload {
            msg: plaintext,
            aad,
        },
    )
    .map_err(|_| "encrypt failed".to_string())
}

pub fn aead_decrypt(
    key: &[u8; 32],
    stream_id: u32,
    counter: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let c = ChaCha20Poly1305::new_from_slice(key).map_err(|_| "bad key".to_string())?;
    c.decrypt(
        &make_nonce(stream_id, counter),
        Payload {
            msg: ciphertext,
            aad,
        },
    )
    .map_err(|_| "decrypt failed (wrong key or corrupt)".to_string())
}

/// Session key from the `BBX_KEY` environment variable, if present and valid.
/// Preferred over `-k` on the remote side: env is not shown by a plain `ps`.
pub(crate) fn env_key() -> Option<[u8; 32]> {
    let s = env::var("BBX_KEY").ok()?;
    parse_key(&s).ok()
}

pub(crate) fn make_nonce(stream_id: u32, counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&stream_id.to_le_bytes());
    n[4..12].copy_from_slice(&counter.to_le_bytes());
    *Nonce::from_slice(&n)
}

pub(crate) fn hash_file(path: &str) -> Result<[u8; 32], String> {
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
