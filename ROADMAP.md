# Roadmap

Honest split: **shipped**, **open for contributors**, **future / hard**.  
Do not claim unfinished items in the README as done.

## Shipped (P0–P4)

| Phase | What |
|-------|------|
| **P0** | Multi-stream BBX2, push/pull, reverse (`-z`), BLAKE3, SPEC, CI |
| **P1** | Data-plane encrypt (ChaCha20-Poly1305 + session `KEY`), install docs |
| **P2** | Resume (`-A`/`-R`), JSON progress (`-J`), `scripts/bench-local.sh` |
| **P3** | Recursive trees (`-r`), this roadmap for contributors |
| **P4** | Empty-file + `pull -r` traversal fixes; I/O + connect + accept timeouts and cross-thread abort (never-hang); remote `~/` expansion; session key via `BBX_KEY` env instead of `-k` on argv |

Protocol: [SPEC.md](SPEC.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Open for contributors (good entry points)

Pick one. Open a PR; update SPEC if the wire changes.

| ID | Item | Difficulty | Notes |
|----|------|------------|--------|
| C1 | ~~Empty file + 1-stream tests~~ · max-streams (64) test still open | easy | empty + 1-stream shipped in P4 CI |
| C2 | Better `BBX_ADVERTISE` / dial-back IP discovery | easy | env today; try default route / iface |
| C3 | Progress on sink during pull | easy | source already has `-P`/`-J` |
| C4 | `--preserve` / `-p` mode+mtime | medium | after write, `chmod`/`utimes` |
| C5 | Rate limit (`-x`) | medium | token bucket on send |
| C6 | Port range bind (`-Z`) | medium | firewall-friendly listen |
| ~~C7~~ | ~~Hide session key from `ps`~~ | done | shipped in P4: `BBX_KEY` env, not `-k` on argv |
| C8 | Windows support | hard | replace `FileExt` / sockbuf path |
| C9 | GitHub Release CI (linux binary) | easy | `gh release` on tag |
| C10 | crates.io publish checklist | easy | name check, README, license |
| C11 | IPv6 `host:path` specs (`[::1]:path`) | medium | `rfind(':')` mis-splits bracketed IPv6 today |
| C12 | Honor sink `-c`/`-C` (or warn) | easy | verification is source-negotiated; sink flag is advisory today |

Label suggestions when filing issues: `good-first-issue`, `protocol`, `ux`, `portability`.

---

## Future / hard (not promised soon)

These stay **explicit non-goals** until someone owns a design + acceptance tests.

| ID | Item | Why deferred |
|----|------|----------------|
| F1 | QUIC data plane | async rewrite; UDP path |
| F2 | TLS/rustls + cert identity | PSK-over-SSH covers lab; heavier auth story |
| F3 | Perfect forward secrecy | long-lived multi-tenant agents |
| F4 | Content-defined chunking / dedup | competes with rsync/rclone scope |
| F5 | S3 / object storage | not a bulk scp tool |
| F6 | bbcp wire compatibility | different protocol by design |
| F7 | Plugin system | YAGNI until multiple real plugins exist |
| F8 | Encrypt control/header metadata | hash still clear on stream 0 today |

---

## P1 leftovers (optional, not blocking)

Called “P1 extras” earlier — **not** required for encrypt-shipped:

- QUIC → **F1**
- TLS certs → **F2**
- crates.io → **C10**
- PFS / hide `-k` → **F3** / **C7**

---

## Version contract

| Version | Meaning |
|---------|---------|
| `0.x` | Working tool; API/flags may grow; limits documented |
| `1.0` | README “supported” list freezes; breaking changes need major bump |

Tag releases when you want downloadable binaries (**C9**), not before CI is green.
