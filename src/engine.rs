//! Transfer engine: sink/source drivers, control header, progress.

use crate::{CONTROL_COUNTER, FLAG_BLAKE3, FLAG_CRYPT, FLAG_PRESERVE, FLAG_RESUME, MAGIC};
use crate::crypto::{aead_decrypt, aead_encrypt, derive_aead_key, frame_aad, gen_key, hash_file, hex};
use crate::frames::{apply_preserve, file_mode_mtime, recv_range, send_range};
use crate::net::{accept_streams, bind_listener, cleartext_allowed, dial_streams};
use crate::util::{read_u32, read_u64, split_ranges, write_u32, write_u64};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) fn print_listen_banner(port: u16, crypt: bool, key: &Option<[u8; 32]>, resume_from: Option<u64>) {
    println!("PORT {port}");
    if crypt {
        let k = key.expect("crypt without key");
        println!("KEY {}", hex(&k));
    }
    if let Some(r) = resume_from {
        println!("RESUME {r}");
    }
    let _ = io::stdout().flush();
}

pub(crate) fn existing_len(path: &str) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

pub(crate) fn run_sink_listen(
    listen: &str,
    port_range: Option<(u16, u16)>,
    out: &str,
    streams: usize,
    wnd: usize,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume: bool,
    json: bool,
    progress: u64,
    rate: u64,
) -> Result<(), String> {
    let key = if crypt {
        Some(key.unwrap_or_else(gen_key))
    } else {
        None
    };
    let have = if resume { Some(existing_len(out)) } else { None };
    if !crypt {
        cleartext_allowed(listen)?;
    }
    let listener = bind_listener(listen, port_range)?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    print_listen_banner(port, crypt, &key, have);
    run_sink_with_listener(
        listener, out, streams, wnd, check, progress, crypt, key, resume, json, rate,
    )
}

pub(crate) fn run_sink_connect(
    addr: &str,
    out: &str,
    streams: usize,
    wnd: usize,
    check: bool,
    progress: u64,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume: bool,
    json: bool,
    rate: u64,
) -> Result<(), String> {
    if crypt && key.is_none() {
        return Err("encrypt needs -k KEY (from peer KEY line)".into());
    }
    if !crypt {
        cleartext_allowed(addr)?;
    }
    let conns = dial_streams(addr, streams, wnd, key.as_ref())?;
    finish_sink(conns, out, streams, check, progress, crypt, key, resume, json, rate)
}

pub(crate) fn run_sink_with_listener(
    listener: TcpListener,
    out: &str,
    streams: usize,
    wnd: usize,
    check: bool,
    progress: u64,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume: bool,
    json: bool,
    rate: u64,
) -> Result<(), String> {
    if !crypt {
        let la = listener
            .local_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        cleartext_allowed(&la)?;
    }
    let conns = accept_streams(&listener, streams, wnd, "sink", key.as_ref())?;
    finish_sink(conns, out, streams, check, progress, crypt, key, resume, json, rate)
}

/// Fresh transfer work path: temp beside dest (same filesystem → atomic rename).
/// Resume writes the real destination path (owns that file while `-A` is active).
pub(crate) fn sink_work_path(out: &str, resume_from: u64) -> Result<(String, bool), String> {
    if resume_from > 0 {
        return Ok((out.to_string(), false));
    }
    let p = Path::new(out);
    let parent = p
        .parent()
        .filter(|x| !x.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let base = p
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("bbx.out");
    let mut rnd = [0u8; 4];
    getrandom::getrandom(&mut rnd).map_err(|e| e.to_string())?;
    let tmp = parent.join(format!(
        ".{base}.bbx.{:08x}.tmp",
        u32::from_le_bytes(rnd)
    ));
    Ok((tmp.to_string_lossy().into_owned(), true))
}

/// On failed transfer: delete temp (fresh) or shrink resume dest to trusted prefix.
pub(crate) fn sink_fail_cleanup(work: &str, resume_from: u64, is_temp: bool) {
    if is_temp || resume_from == 0 {
        let _ = std::fs::remove_file(work);
    } else if let Ok(f) = OpenOptions::new().write(true).open(work) {
        let _ = f.set_len(resume_from);
    }
}

pub(crate) fn finish_sink(
    mut conns: Vec<TcpStream>,
    out: &str,
    streams_hint: usize,
    check: bool,
    progress: u64,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume: bool,
    json: bool,
    rate: u64,
) -> Result<(), String> {
    let mut ctrl = conns.remove(0);
    let mut magic = [0u8; 4];
    ctrl.read_exact(&mut magic).map_err(|e| e.to_string())?;
    if &magic != MAGIC {
        return Err(format!("bad magic {:?} (need BBX2; upgrade both ends)", magic));
    }
    let flags = read_u32(&mut ctrl)?;
    let size = read_u64(&mut ctrl)?;
    let n = read_u32(&mut ctrl)? as usize;
    if n == 0 || n > 64 {
        return Err("bad stream count".into());
    }
    let want_check = flags & FLAG_BLAKE3 != 0;
    let want_crypt = flags & FLAG_CRYPT != 0;
    let want_resume = flags & FLAG_RESUME != 0;
    let want_preserve = flags & FLAG_PRESERVE != 0;
    let resume_from = if want_resume {
        read_u64(&mut ctrl)?
    } else {
        0
    };
    if want_crypt != crypt {
        return Err(format!(
            "crypt mismatch: local={} peer={}",
            crypt, want_crypt
        ));
    }
    if want_crypt && key.is_none() {
        return Err("peer sent FLAG_CRYPT but no session key".into());
    }
    // Per-transfer salt (FLAG_CRYPT): derive AEAD key so reused PSKs never share nonce space.
    let (aead_key, salt, frame_aad_bytes) = if want_crypt {
        let mut salt = [0u8; 32];
        ctrl.read_exact(&mut salt).map_err(|e| e.to_string())?;
        let ak = derive_aead_key(key.as_ref().unwrap(), &salt);
        let aad = frame_aad(flags, size, n as u32, resume_from, &salt);
        (Some(ak), Some(salt), Some(aad))
    } else {
        (None, None, None)
    };
    if resume_from > size {
        return Err(format!("resume_from {resume_from} > size {size}"));
    }
    let _ = resume; // peer may resume even if local -A unset
    // C12: local -c/-C vs peer FLAG_BLAKE3
    if check && !want_check {
        return Err(
            "source did not enable BLAKE3 (need matching -c on source, or pass -C to skip check)"
                .into(),
        );
    }
    if !check && want_check && !json {
        eprintln!("bbx: warning: local -C ignored (source sent FLAG_BLAKE3; verifying)");
    }
    // Resume trusts prefix length; full-file BLAKE3 is the integrity backstop.
    if resume_from > 0 && !want_check {
        return Err(
            "resume requires BLAKE3 (-c): prefix is not re-hashed alone; refuse unsafe resume"
                .into(),
        );
    }
    let streams = n;
    if streams_hint != 0 && streams_hint != streams {
        return Err(format!(
            "stream count mismatch: local -s {streams_hint}, peer {streams}"
        ));
    }
    let mut all = Vec::with_capacity(streams);
    all.push(ctrl);
    all.append(&mut conns);
    if all.len() != streams {
        return Err(format!("expected {streams} streams, got {}", all.len()));
    }

    // Sensitive control fields: clear when !crypt; AEAD-sealed when crypt (F8).
    let (expect_hash, meta_mode, meta_mtime) = if want_crypt {
        let aead = aead_key.as_ref().unwrap();
        let aad = frame_aad_bytes.as_ref().unwrap();
        let clen = read_u32(&mut all[0])? as usize;
        if clen > 256 {
            return Err(format!("bad sealed control len {clen}"));
        }
        let mut ct = vec![0u8; clen];
        all[0]
            .read_exact(&mut ct)
            .map_err(|e| e.to_string())?;
        let pt = aead_decrypt(aead, 0, CONTROL_COUNTER, &ct, aad)?;
        let mut off = 0usize;
        let mut expect_hash = [0u8; 32];
        let mut have_hash = false;
        if want_check {
            if pt.len() < off + 32 {
                return Err("sealed control short (hash)".into());
            }
            expect_hash.copy_from_slice(&pt[off..off + 32]);
            off += 32;
            have_hash = true;
        }
        let (meta_mode, meta_mtime) = if want_preserve {
            if pt.len() < off + 12 {
                return Err("sealed control short (preserve)".into());
            }
            let mode = u32::from_le_bytes(pt[off..off + 4].try_into().unwrap());
            let mtime = u64::from_le_bytes(pt[off + 4..off + 12].try_into().unwrap());
            (Some(mode), Some(mtime))
        } else {
            (None, None)
        };
        let _ = have_hash;
        let _ = salt;
        (
            if want_check { Some(expect_hash) } else { None },
            meta_mode,
            meta_mtime,
        )
    } else {
        let mut expect_hash = None;
        if want_check {
            let mut h = [0u8; 32];
            all[0].read_exact(&mut h).map_err(|e| e.to_string())?;
            expect_hash = Some(h);
        }
        let (meta_mode, meta_mtime) = if want_preserve {
            let mode = read_u32(&mut all[0])?;
            let mtime = read_u64(&mut all[0])?;
            (Some(mode), Some(mtime))
        } else {
            (None, None)
        };
        (expect_hash, meta_mode, meta_mtime)
    };

    let have = existing_len(out);
    if resume_from > 0 {
        if have < resume_from {
            return Err(format!(
                "local file shorter than resume_from ({have} < {resume_from})"
            ));
        }
    }
    let (work_path, is_temp) = sink_work_path(out, resume_from)?;
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(resume_from == 0)
        .open(&work_path)
        .map_err(|e| e.to_string())?;
    if resume_from > 0 && have > resume_from {
        file.set_len(resume_from).map_err(|e| e.to_string())?;
    }
    file.set_len(size).map_err(|e| e.to_string())?;

    let transfer = (|| -> Result<(), String> {
        let remaining = size - resume_from;
        let ranges = split_ranges(remaining, streams)
            .into_iter()
            .map(|(a, b)| (a + resume_from, b + resume_from))
            .collect::<Vec<_>>();
        let file = Arc::new(file);
        let got = Arc::new(AtomicU64::new(resume_from));
        let t0 = Instant::now();
        let key = aead_key.map(Arc::new);
        let aad = frame_aad_bytes.map(Arc::new);
        let rate_start = Instant::now();
        let (pb, prog_stop, prog_thr) =
            start_progress(Arc::clone(&got), size, progress, json, t0);

        let abort = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        for (i, mut sock) in all.into_iter().enumerate() {
            let (start, end) = ranges[i];
            let f = Arc::clone(&file);
            let g = Arc::clone(&got);
            let k = key.clone();
            let a = aad.clone();
            let ab = Arc::clone(&abort);
            handles.push(thread::spawn(move || -> Result<(), String> {
                let r = recv_range(
                    &mut sock,
                    &f,
                    start,
                    end,
                    i as u32,
                    k.as_deref(),
                    a.as_deref().map(|v| v.as_slice()),
                    &g,
                    &ab,
                    rate,
                    rate_start,
                );
                if r.is_err() {
                    ab.store(true, Ordering::Relaxed);
                }
                r
            }));
        }
        let join_r = (|| -> Result<(), String> {
            for h in handles {
                h.join().map_err(|_| "thread panic".to_string())??;
            }
            Ok(())
        })();
        if join_r.is_err() {
            stop_progress(pb, &prog_stop, prog_thr);
            join_r?;
        } else {
            // Finish bar before verify messages so stderr stays readable.
            finish_progress(pb, &prog_stop, prog_thr, size, t0, json);
        }
        if let Some(expect_hash) = expect_hash {
            if !json {
                eprint!("bbx: verifying BLAKE3… ");
                let _ = io::stderr().flush();
            }
            let got_hash = hash_file(&work_path)?;
            if got_hash != expect_hash {
                if resume_from > 0 {
                    return Err(format!(
                        "checksum mismatch after resume (expected {} got {}); \
                         local prefix is not re-checked alone — delete {} and retry a full transfer \
                         (do not re-run -A on a corrupt partial)",
                        hex(&expect_hash),
                        hex(&got_hash),
                        out
                    ));
                }
                return Err(format!(
                    "checksum mismatch: expected {} got {}",
                    hex(&expect_hash),
                    hex(&got_hash)
                ));
            }
            if !json {
                eprintln!("ok");
            }
        }
        if let (Some(mode), Some(mtime)) = (meta_mode, meta_mtime) {
            apply_preserve(&work_path, mode, mtime)?;
        }
        // Atomic replace of final dest only after success (fresh transfers).
        if is_temp {
            std::fs::rename(&work_path, out).map_err(|e| {
                format!("rename {} → {}: {e}", work_path, out)
            })?;
        }
        if json {
            println!(
                r#"{{"event":"done","bytes":{size},"total":{size},"resumed_from":{resume_from}}}"#
            );
        }
        Ok(())
    })();

    if transfer.is_err() {
        sink_fail_cleanup(&work_path, resume_from, is_temp);
    }
    transfer
}

pub(crate) fn run_source_connect(
    addr: &str,
    input: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume_from: u64,
    json: bool,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    if crypt && key.is_none() {
        return Err("encrypt needs session KEY from peer".into());
    }
    if !crypt {
        cleartext_allowed(addr)?;
    }
    let conns = dial_streams(addr, streams, wnd, key.as_ref())?;
    finish_source(
        conns, input, streams, progress, check, crypt, key, resume_from, json, preserve, rate,
    )
}

pub(crate) fn run_source_listen(
    listen: &str,
    port_range: Option<(u16, u16)>,
    input: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume_from: u64,
    json: bool,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    let key = if crypt {
        Some(key.unwrap_or_else(gen_key))
    } else {
        None
    };
    if !crypt {
        cleartext_allowed(listen)?;
    }
    let listener = bind_listener(listen, port_range)?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    print_listen_banner(port, crypt, &key, None);
    run_source_with_listener(
        listener, input, streams, wnd, progress, check, crypt, key, resume_from, json, preserve,
        rate,
    )
}

pub(crate) fn run_source_with_listener(
    listener: TcpListener,
    input: &str,
    streams: usize,
    wnd: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume_from: u64,
    json: bool,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    if !crypt {
        let la = listener
            .local_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        cleartext_allowed(&la)?;
    }
    let conns = accept_streams(&listener, streams, wnd, "source", key.as_ref())?;
    finish_source(
        conns, input, streams, progress, check, crypt, key, resume_from, json, preserve, rate,
    )
}

pub(crate) fn finish_source(
    mut conns: Vec<TcpStream>,
    input: &str,
    streams: usize,
    progress: u64,
    check: bool,
    crypt: bool,
    key: Option<[u8; 32]>,
    resume_from: u64,
    json: bool,
    preserve: bool,
    rate: u64,
) -> Result<(), String> {
    if conns.len() != streams {
        return Err(format!("expected {streams} streams, got {}", conns.len()));
    }
    if crypt && key.is_none() {
        return Err("encrypt needs key".into());
    }
    let file = File::open(input).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    let size = meta.len();
    if resume_from > size {
        return Err(format!("resume_from {resume_from} > file size {size}"));
    }
    // Always send the control header (even when remaining == 0) so the sink can
    // create/set_len, verify BLAKE3, and apply --preserve. Never trust length-only skip.

    let hash = if check {
        if !json {
            eprint!("bbx: hashing BLAKE3… ");
            let _ = io::stderr().flush();
        }
        let h = hash_file(input)?;
        if !json {
            eprintln!("ok");
        }
        Some(h)
    } else {
        None
    };

    let file_meta = if preserve {
        Some(file_mode_mtime(&meta)?)
    } else {
        None
    };

    let mut ctrl = &mut conns[0];
    ctrl.write_all(MAGIC).map_err(|e| e.to_string())?;
    let mut flags = 0u32;
    if check {
        flags |= FLAG_BLAKE3;
    }
    if crypt {
        flags |= FLAG_CRYPT;
    }
    if resume_from > 0 {
        flags |= FLAG_RESUME;
    }
    if preserve {
        flags |= FLAG_PRESERVE;
    }
    if resume_from > 0 && !check {
        return Err(
            "resume requires BLAKE3 (-c): refuse sending resume without integrity".into(),
        );
    }
    write_u32(&mut ctrl, flags)?;
    write_u64(&mut ctrl, size)?;
    write_u32(&mut ctrl, streams as u32)?;
    if resume_from > 0 {
        write_u64(&mut ctrl, resume_from)?;
    }
    // Per-transfer salt under FLAG_CRYPT → unique AEAD key even if PSK is reused.
    let (aead_key, frame_aad_bytes) = if crypt {
        let salt = gen_key();
        ctrl.write_all(&salt).map_err(|e| e.to_string())?;
        let ak = derive_aead_key(key.as_ref().unwrap(), &salt);
        let aad = frame_aad(flags, size, streams as u32, resume_from, &salt);
        // Seal blake3 + preserve under AEAD (F8); salt stays clear (needed to derive).
        let mut plain = Vec::new();
        if let Some(h) = hash {
            plain.extend_from_slice(&h);
        }
        if let Some((mode, mtime)) = file_meta {
            plain.extend_from_slice(&mode.to_le_bytes());
            plain.extend_from_slice(&mtime.to_le_bytes());
        }
        // Always send sealed blob when crypt (may be empty pt → tag only) so wire is uniform.
        let ct = aead_encrypt(&ak, 0, CONTROL_COUNTER, &plain, &aad)?;
        write_u32(&mut ctrl, ct.len() as u32)?;
        ctrl.write_all(&ct).map_err(|e| e.to_string())?;
        (Some(ak), Some(aad))
    } else {
        if let Some(h) = hash {
            ctrl.write_all(&h).map_err(|e| e.to_string())?;
        }
        if let Some((mode, mtime)) = file_meta {
            write_u32(&mut ctrl, mode)?;
            write_u64(&mut ctrl, mtime)?;
        }
        (None, None)
    };

    let remaining = size - resume_from;
    let ranges = split_ranges(remaining, streams)
        .into_iter()
        .map(|(a, b)| (a + resume_from, b + resume_from))
        .collect::<Vec<_>>();
    let sent = Arc::new(AtomicU64::new(resume_from));
    let t0 = Instant::now();
    let rate_start = Instant::now();
    let file = Arc::new(file);
    let key = aead_key.map(Arc::new);
    let aad = frame_aad_bytes.map(Arc::new);

    let (pb, prog_stop, prog_thr) =
        start_progress(Arc::clone(&sent), size, progress, json, t0);

    let abort = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    for (i, mut sock) in conns.into_iter().enumerate() {
        let (start, end) = ranges[i];
        let f = Arc::clone(&file);
        let sent_c = Arc::clone(&sent);
        let k = key.clone();
        let a = aad.clone();
        let ab = Arc::clone(&abort);
        handles.push(thread::spawn(move || -> Result<(), String> {
            let r = send_range(
                &mut sock,
                &f,
                start,
                end,
                i as u32,
                k.as_deref(),
                a.as_deref().map(|v| v.as_slice()),
                &sent_c,
                &ab,
                rate,
                rate_start,
            );
            if r.is_err() {
                ab.store(true, Ordering::Relaxed);
            }
            r
        }));
    }
    let body = (|| -> Result<(), String> {
        for h in handles {
            h.join().map_err(|_| "thread panic".to_string())??;
        }
        Ok(())
    })();
    match &body {
        Ok(()) => finish_progress(pb, &prog_stop, prog_thr, size, t0, json),
        Err(_) => stop_progress(pb, &prog_stop, prog_thr),
    }
    body?;
    let elapsed = t0.elapsed().as_secs_f64().max(0.001);
    if json {
        println!(
            r#"{{"event":"done","bytes":{size},"total":{size},"secs":{elapsed:.3},"resumed_from":{resume_from},"encrypted":{}}}"#,
            if crypt { "true" } else { "false" }
        );
    } else {
        eprintln!(
            "bbx: done {} bytes in {:.2}s ({:.1} MB/s){}{}",
            size,
            elapsed,
            size as f64 / elapsed / 1024.0 / 1024.0,
            if crypt { " [encrypted]" } else { "" },
            if resume_from > 0 {
                format!(" [resumed from {resume_from}]")
            } else {
                String::new()
            }
        );
    }
    Ok(())
}

fn make_progress_bar(size: u64, initial: u64) -> ProgressBar {
    let pb = ProgressBar::new(size);
    pb.set_position(initial);
    pb.set_style(
        ProgressStyle::with_template(
            "bbx: [{bar:24.cyan/blue}] {percent:>3}%  {bytes_per_sec}  ETA {eta}",
        )
        .expect("progress template")
        .progress_chars("##-"),
    );
    pb
}

/// `-J`: JSON on the `-P` interval. Else: indicatif bar (~4 updates/s while `-P` > 0).
fn start_progress(
    counter: Arc<AtomicU64>,
    size: u64,
    interval_secs: u64,
    json: bool,
    t0: Instant,
) -> (Option<ProgressBar>, Arc<AtomicBool>, Option<JoinHandle<()>>) {
    let stop = Arc::new(AtomicBool::new(false));
    if interval_secs == 0 {
        return (None, stop, None);
    }
    if json {
        let stop_t = Arc::clone(&stop);
        let thr = thread::spawn(move || loop {
            if stop_t.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_secs(interval_secs.max(1)));
            if stop_t.load(Ordering::Relaxed) {
                break;
            }
            let n = counter.load(Ordering::Relaxed);
            // Final 100% JSON line comes from finish_progress only.
            if n >= size {
                break;
            }
            report_progress_json(n, size, t0);
        });
        (None, stop, Some(thr))
    } else {
        let pb = make_progress_bar(size, counter.load(Ordering::Relaxed));
        let pb2 = pb.clone();
        let stop_t = Arc::clone(&stop);
        let thr = thread::spawn(move || loop {
            if stop_t.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_millis(250));
            if stop_t.load(Ordering::Relaxed) {
                break;
            }
            let n = counter.load(Ordering::Relaxed);
            // Leave 100% draw to finish_progress — avoids a duplicate final line.
            if n >= size {
                break;
            }
            // Skip if main already finished — set_position on a finished bar force-redraws.
            if pb2.is_finished() {
                break;
            }
            pb2.set_position(n);
        });
        (Some(pb), stop, Some(thr))
    }
}

fn join_progress(stop: &AtomicBool, thr: Option<JoinHandle<()>>) {
    stop.store(true, Ordering::Relaxed);
    if let Some(t) = thr {
        let _ = t.join();
    }
}

fn stop_progress(pb: Option<ProgressBar>, stop: &AtomicBool, thr: Option<JoinHandle<()>>) {
    join_progress(stop, thr);
    if let Some(pb) = pb {
        pb.set_draw_target(ProgressDrawTarget::hidden());
        pb.abandon();
    }
}

fn finish_progress(
    pb: Option<ProgressBar>,
    stop: &AtomicBool,
    thr: Option<JoinHandle<()>>,
    size: u64,
    t0: Instant,
    json: bool,
) {
    // Join updater first so it cannot set_position after finish() (that force-redraws).
    join_progress(stop, thr);
    if json {
        report_progress_json(size, size, t0);
    } else if let Some(pb) = pb {
        pb.finish();
    }
}

fn report_progress_json(n: u64, size: u64, t0: Instant) {
    let elapsed = t0.elapsed().as_secs_f64().max(0.001);
    let rate = (n as f64 / elapsed) / (1024.0 * 1024.0);
    println!(r#"{{"event":"progress","bytes":{n},"total":{size},"rate_mbps":{rate:.3}}}"#);
}
