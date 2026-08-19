# Roadmap

Honest split: **shipped**, **open**, **out of scope for now**.

## Shipped

| Phase | What |
|-------|------|
| **P0–P4** | Multi-stream BBX2, push/pull/`-z`, BLAKE3, encrypt, resume, JSON, `-r`, timeouts/abort, `~/` expand, `BBX_KEY` env |
| **W1** | Listen port range `-Z` / `BBX_PORT_RANGE` |
| **W2** | `BBX_ADVERTISE` + route-toward-remote + default-route IP guess |
| **W3** | `scripts/install-remote.sh` + deploy docs |
| **W5** | Agent kill on failure; non-zero remote exit reported; timeout docs |
| **W4/W6** | README scope: TCP multi-stream internal tool; no crates.io |
| **0.7.0** | Stream-id handshake (fix multi-stream reorder / decrypt / bad magic); wrong-key fail-closed test; musl-first install |
| **Sec A** | `install-remote` DEST validation; PSK+salt AEAD derive; resume requires BLAKE3; `BBX_BIND`/`BBX_PEER_ALLOW`; `BBX_ADVERTISE` validation; agent wait `BBX_AGENT_WAIT_SECS`; C12 sink `-c`/`-C` honor/warn |
| **Sec B** | C1 max-streams 64 test; C3 sink progress reverse/connect pull; C4 `--preserve` mode+mtime; C5 rate limit `-x`; C9 GitHub Release musl binary on `v*` tags; C11 IPv6 `[host]:path`; tree `-r` 1 stream for small files + batch remote mkdir; partial dest cleanup on sink failure |
| **Sec C** | F8 sealed control meta under crypt; stream-id PSK MAC; payload AEAD AAD binds header; cleartext non-loopback refused (`BBX_ALLOW_CLEAR=1` override) |
| **0.8.0** | Sec A+B+C security/correctness batch; encrypt wire break vs 0.7.x |
| **0.8.1** | Fresh sink writes temp-then-rename (failed overwrite keeps dest); `-r` pull NUL listing; refuse symlink path components under dest |
| **C8 partial** | Windows: `FileExt` cfg only (not full support) |

Protocol: [SPEC.md](SPEC.md).

## Open

| ID | Item | Notes |
|----|------|--------|
| C8 | Windows | hard; only `FileExt` cfg so far |

## Closed — will not implement (product boundary)

These were research “gaps” that are **out of product scope**, not deferred bugs:

| ID | Item | Why closed |
|----|------|------------|
| F1 | QUIC data plane | Opposite of TCP/firewall wedge; different product |
| F2 | TLS/cert identity | PSK-over-SSH + Sec C data-plane crypto is the model |
| F4 | Delta/dedup | rsync/`sy` territory |
| F5 | S3 | Not this tool |
| F6 | bbcp wire compat | Different protocol by design |
| C10 | crates.io publish | Name `bbx` taken (BBCode); binary releases via GitHub (C9) |

## Version

| Version | Meaning |
|---------|---------|
| `0.x` | Working tool; flags may grow |
| `1.0` | Supported list freezes |
