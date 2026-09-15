//! bbx library — multi-stream bulk copy (BBX2).
//! Split into focused modules; see SPEC.md for the wire protocol.

use std::time::Duration;

pub mod cli;
pub mod crypto;
pub mod net;
pub mod ssh;
pub mod commands;
pub mod tree;
pub mod cp;
pub mod engine;
pub mod frames;
pub mod util;

// --- shared constants ---
pub const MAGIC: &[u8; 4] = b"BBX2";
pub const DEFAULT_STREAMS: usize = 4;
pub const DEFAULT_WND: usize = 4 * 1024 * 1024;
pub const CHUNK: usize = 1024 * 1024;
pub const CRYPT_PT: usize = 64 * 1024;
pub const FLAG_BLAKE3: u32 = 1;
pub const FLAG_CRYPT: u32 = 2;
pub const FLAG_RESUME: u32 = 4;
pub const FLAG_PRESERVE: u32 = 8;
/// Tree mode: files smaller than this use a single stream (cuts multi-stream races on tiny files).
pub const TREE_SINGLE_STREAM_MAX: u64 = 1024 * 1024;
/// Reserved AEAD counter for sealed control meta (payload counters start at 0).
pub const CONTROL_COUNTER: u64 = u64::MAX;
/// Stream-id MAC tag length (BLAKE3 keyed truncate).
pub const SID_TAG_LEN: usize = 16;
pub const IO_TIMEOUT_SECS: u64 = 120;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(test)]
mod tests;
