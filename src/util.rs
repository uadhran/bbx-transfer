//! Low-level helpers: range splitting, positional file IO, integer wire codecs.

use std::fs::File;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

pub fn split_ranges(size: u64, n: usize) -> Vec<(u64, u64)> {
    let n = n as u64;
    let base = size / n;
    let mut rem = size % n;
    let mut out = Vec::with_capacity(n as usize);
    let mut start = 0u64;
    for _ in 0..n {
        let extra = if rem > 0 {
            rem -= 1;
            1
        } else {
            0
        };
        let end = start + base + extra;
        out.push((start, end));
        start = end;
    }
    out
}

pub(crate) fn read_at_full(f: &File, buf: &mut [u8], mut off: u64) -> Result<(), String> {
    let mut got = 0;
    while got < buf.len() {
        #[cfg(unix)]
        let n = f.read_at(&mut buf[got..], off).map_err(|e| e.to_string())?;
        #[cfg(windows)]
        let n = f.seek_read(&mut buf[got..], off).map_err(|e| e.to_string())?;
        #[cfg(not(any(unix, windows)))]
        let n = {
            use std::io::{Read, Seek, SeekFrom};
            let mut f2 = f.try_clone().map_err(|e| e.to_string())?;
            f2.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
            f2.read(&mut buf[got..]).map_err(|e| e.to_string())?
        };
        if n == 0 {
            return Err("unexpected EOF".into());
        }
        got += n;
        off += n as u64;
    }
    Ok(())
}

pub(crate) fn write_at_full(f: &File, buf: &[u8], mut off: u64) -> Result<(), String> {
    let mut put = 0;
    while put < buf.len() {
        #[cfg(unix)]
        let n = f.write_at(&buf[put..], off).map_err(|e| e.to_string())?;
        #[cfg(windows)]
        let n = f.seek_write(&buf[put..], off).map_err(|e| e.to_string())?;
        #[cfg(not(any(unix, windows)))]
        let n = {
            use std::io::{Seek, SeekFrom, Write};
            let mut f2 = f.try_clone().map_err(|e| e.to_string())?;
            f2.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
            f2.write(&buf[put..]).map_err(|e| e.to_string())?
        };
        if n == 0 {
            return Err("short write".into());
        }
        put += n;
        off += n as u64;
    }
    Ok(())
}

pub(crate) fn read_u64(r: &mut impl Read) -> Result<u64, String> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes(b))
}

pub(crate) fn read_u32(r: &mut impl Read) -> Result<u32, String> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u32::from_le_bytes(b))
}

pub(crate) fn write_u32(w: &mut impl Write, v: u32) -> Result<(), String> {
    w.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}

pub(crate) fn write_u64(w: &mut impl Write, v: u64) -> Result<(), String> {
    w.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())
}
