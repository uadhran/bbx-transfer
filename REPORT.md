# bbx benchmark report

**Tool:** [bbx](https://github.com/uadhran/bbx-transfer) (CLI binary `bbx`) — multi-stream TCP bulk file copy (BBX2), optional BLAKE3 integrity and ChaCha20-Poly1305 encryption.  
**Report date:** 2026-07-30  
**Run ID:** `20260729T144307Z`  
**Purpose:** Measure real throughput and fitness of `bbx` vs common tools on a live lab WAN path, for internal use and pitch.

---

## 1. Executive summary

| Scenario | Winner | Headline |
|----------|--------|----------|
| **Large file WAN push** | **bbx** | ~**1.6–1.7×** scp / typical rsync |
| **Large file WAN pull** | **bbx** | ~**3×** scp / rsync |
| **Encrypt vs clear (large WAN)** | Tie | Negligible difference on this link |
| **Many tiny files / trees** | **rsync** | bbx `-r` is one session per file; hours vs seconds |
| **Local disk copy** | rsync / `cp` | bbx loopback is TCP+protocol, not pure disk |

**Pitch in one line:**  
On high-latency / multi-stream-friendly WAN bulk transfers of large files, **bbx delivers ~1.6× push and ~3× pull vs scp/rsync**, with encryption nearly free; it is **not** a replacement for rsync on metadata-heavy trees.

---

## 2. Environment & method

### 2.1 Setup

| Item | Value |
|------|--------|
| Client | Linux x86_64 workstation |
| Server | Separate Linux host on lab network (BatchMode SSH) |
| Path type | Live shared WAN-style link (not a quiet isolated lab) |
| bbx client | musl static release (portable across glibc versions) |
| bbx server | Same version binary on remote |
| Streams | **8** (`-s 8`) |
| Timer | Wall clock + `/usr/bin/time -v` (RSS, %CPU where captured) |
| Throughput | `bytes / wall_seconds` → MiB/s |
| Runs | **3** for ~760 MiB cells; **1** for 2 GiB cells |
| Aggregate | **Median** of OK runs |

### 2.2 Datasets

| Name | Contents | Approx size |
|------|----------|-------------|
| **large760** | Real analytics CSV | ~760 MiB (796 636 939 B) |
| **large2g** | `/dev/urandom` blob | 2 GiB |
| **tiny5k** | 5000 × 2 KiB files | ~10 MiB payload |
| **nested** | Depth-12 chain + small bush | ~1.2 MiB |

### 2.3 Tools compared

| Tool | Config |
|------|--------|
| **scp** | `Compression=no` |
| **rsync** | `-a` over SSH (default) |
| **rsync “pt5”** | `-aHAXx` + `aes128-gcm@openssh.com` + `Compression=no` |
| **bbx clear** | `-s 8 -C -E` (no hash, no encrypt) |
| **bbx enc** | `-s 8 -e -c` (ChaCha20-Poly1305 + BLAKE3) |
| **bbx trees** | `-r` + same clear/enc flags |
| **bbcp** | Intended `-s 8` — **not available this run** |

### 2.4 Directions

- **Local:** disk copy / loopback (context only)  
- **WAN push:** client → server  
- **WAN pull:** server → client  
- **Correctness:** bad path, wrong key, resume (`-A`)

### 2.5 Caveats (read before pitching)

1. **Single path, live network** — numbers are for this environment; other links will differ.  
2. **Not multi-host mesh** and not multi-day averages — medians of 1–3 runs.  
3. **large760 rsync push** completed in ~1.6 s (~470 MiB/s): **not trusted** on this link (scp/bbx/2 GiB rsync are consistent). **Do not quote that cell.**  
4. **bbcp** failed every cell (local helper binary missing). No bbcp comparison.  
5. **tiny bbx encrypt** and **tiny bbx pull** had failures (decrypt / partial tree) — treat tree path as immature for pitch.  
6. **Wrong-key encrypt** (this run): did **not** fail closed (`rc=0`). **Note (post-report):** **0.7.0+ / current code is fail-closed** (`crypt_loopback` + AEAD); do not treat this historical result as current behavior.

---

## 3. Results

### 3.1 Local (not the product story)

| Dataset | Tool | Median rate | Median time |
|---------|------|-------------|-------------|
| large760 | rsync `-aHAXxW --no-compress` | ~16 GiB/s | ~0.05 s |
| large760 | `cp` | ~3.7 GiB/s | ~0.2 s |
| large760 | bbx loopback `-s8` clear | ~553 MiB/s | ~1.4 s |
| tiny5k / nested | rsync | ~30 / ~21 MiB/s | sub-second |

**Interpretation:** Local pure disk favors rsync/`cp`. bbx loopback pays TCP + protocol overhead. **Do not pitch bbx for same-host copy.**

---

### 3.2 WAN — large single files (headline)

#### ~760 MiB (median of 3 OK runs)

| Direction | scp | rsync default | rsync pt5 | **bbx clear** | **bbx enc** |
|-----------|-----|---------------|-----------|---------------|-------------|
| **Push** | 2.47 MiB/s (~307 s) | *exclude* | *exclude* | **4.03 MiB/s (~189 s)** | **4.19 MiB/s (~181 s)** |
| **Pull** | 1.02 MiB/s (~743 s) | 1.02 MiB/s (~744 s) | 1.10 MiB/s (~690 s) | **3.25 MiB/s (~234 s)** | **2.92 MiB/s (~260 s)** |

#### 2 GiB (single run)

| Direction | scp | rsync default | rsync pt5 | **bbx clear** | **bbx enc** |
|-----------|-----|---------------|-----------|---------------|-------------|
| **Push** | 2.64 MiB/s (~777 s) | 2.71 MiB/s (~756 s) | 2.81 MiB/s (~728 s) | **4.55 MiB/s (~451 s)** | **4.52 MiB/s (~453 s)** |
| **Pull** | 1.00 MiB/s (~2055 s) | 0.97 MiB/s (~2111 s) | 0.94 MiB/s (~2172 s) | **3.20 MiB/s (~641 s)** | **3.10 MiB/s (~661 s)** |

#### Speedup summary (large WAN, trustworthy cells)

| Metric | Approx factor |
|--------|----------------|
| bbx push vs scp | **~1.6–1.7×** |
| bbx push vs rsync (2 GiB) | **~1.6–1.7×** |
| bbx pull vs scp / rsync | **~3.0–3.4×** |
| bbx enc vs bbx clear | **~1.0×** (within noise) |

**Time example (2 GiB pull):** scp ~34 min → bbx clear ~11 min.

---

### 3.3 WAN — many small files (anti-pitch for wrong use)

**tiny5k** (5000 × 2 KiB):

| Tool | Push (median) |
|------|----------------|
| rsync | ~2.2 s (~4.5 MiB/s) |
| bbx `-r` clear | **~4.2 hours** (~0 MiB/s effective) |

**nested** (~63 small files):

| Tool | Push | Pull |
|------|------|------|
| rsync | ~1.6–1.7 s | ~3.4 s |
| bbx `-r` | ~191 s | ~113 s |

**Interpretation:** bbx recursive mode is **sequential multi-session**. Fine for a handful of large files; **wrong tool** for “millions of small files” or rsync-style trees. Pitch **honestly** with this limit.  
*(Post-report: tree mid-fail mitigations — 1 stream for small files, batch remote mkdir, partial dest cleanup on sink failure.)*

---

### 3.4 Correctness (functional, not speed)

| Test | Result | Notes |
|------|--------|--------|
| Bad source path | **OK** | Non-zero exit as expected |
| Wrong encryption key on pull | **FAIL** (this run) | Did not reject (`rc=0`). **Fixed in 0.7.0+** — fail-closed via AEAD / `crypt_loopback` |
| Resume `-A` after partial dest | **OK** | Full file compares equal |

---

### 3.5 Failures & missing data

| Item | Status |
|------|--------|
| bbcp all cells | FAIL — helper binary not present for harness |
| tiny5k bbx enc push (×3) | FAIL — decrypt/corrupt errors mid-tree |
| tiny5k bbx clear pull (×3) | FAIL — failed mid tree pull |
| large760 rsync push | Measured but **not cited** (implausible rate) |

---

## 4. Why bbx can be faster (large WAN)

Without overselling:

1. **Multiple TCP streams** (`-s N`) fill the pipe better when a single SSH/scp/rsync stream is latency- or window-limited.  
2. **Data plane off SSH** after bootstrap — SSH starts the remote agent; bulk bytes ride parallel TCP.  
3. **Encrypt/hash** are stream-friendly (ChaCha20-Poly1305 / BLAKE3); on this link they did not dominate.  
4. **Tradeoff:** setup cost per file is high → tiny-file `-r` suffers.

---

## 5. When to use bbx (pitch framing)

### Use bbx when

- Moving **large** files (hundreds of MiB → multi-GiB) across **WAN / high-latency** links  
- You control **both ends** and can install the same `bbx` binary  
- **UDP/QUIC tools** are blocked or painful; you want **plain multi-stream TCP**  
- Optional **encrypt + integrity** without much throughput loss on your path  

### Do **not** use bbx when

- **Incremental / delta sync** or attribute-heavy trees → **rsync** (or similar)  
- **Thousands of tiny files** as the main workload → rsync  
- **Same-machine** disk copy → `cp` / rsync  
- You need a **bbcp wire-compatible** drop-in (different protocol by design)  

### Deploy note (ops)

Building on a newer glibc host can break older remotes. **Musl static** build installs cleanly across glibc generations:

```bash
cargo build --release --target x86_64-unknown-linux-musl
./scripts/install-remote.sh user@host /path/to/bbx
export BBX_REMOTE=/path/to/bbx
```

---

## 6. Pitch slide bullets (copy-ready)

1. **bbx** is a multi-stream TCP bulk copier (SSH bootstrap, open BBX2 protocol).  
2. On our lab WAN, **large-file pull ~3× scp/rsync; push ~1.6×**.  
3. **Encryption + BLAKE3 ≈ free** vs clear on that path.  
4. **Not rsync:** tiny-file trees are a known non-goal / weak area.  
5. **Portable deploy** via musl binary; same version both ends.  
6. **Honest limits:** live single-path medians; bbcp not compared. (Wrong-key fail-open in this run is fixed in 0.7.0+.)

---

## 7. Raw data & reproducibility

| Artifact | Location (local workspace) |
|----------|----------------------------|
| CSV | `bench/results/results_20260729T144307Z.csv` |
| Console log | `bench/results/console_20260729T144307Z.log` |
| Harness | `bench/run_full_bench.sh` (**local only**, not in public git — host-specific) |

Public product docs: [README.md](README.md), [SPEC.md](SPEC.md), release [v0.6.0](https://github.com/uadhran/bbx-transfer/releases/tag/v0.6.0).

---

## 8. Conclusion

The benchmark supports a clear, defensible story:

> **For large-file bulk transfer over our WAN, bbx is materially faster than scp and rsync (especially pull), with multi-stream TCP and cheap optional crypto. It is a specialist tool, not a general rsync replacement.**

Use the **2 GiB** and **760 MiB pull** tables as primary evidence; call out tree/tiny-file limits and caveats up front so the pitch stays credible.
