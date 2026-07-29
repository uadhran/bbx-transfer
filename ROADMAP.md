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

Protocol: [SPEC.md](SPEC.md).

## Open

| ID | Item | Notes |
|----|------|--------|
| C1 | max-streams (64) integration test | easy |
| C3 | Progress on sink during pull | easy |
| C4 | `--preserve` mode+mtime | medium |
| C5 | Rate limit `-x` | medium |
| C8 | Windows | hard |
| C9 | GitHub Release binary CI | easy; no crates.io |
| C11 | IPv6 `host:path` for `cp` | medium |
| C12 | Honor sink `-c`/`-C` or warn | easy |

## Explicit non-goals (now)

| ID | Item | Why |
|----|------|-----|
| F1 | QUIC data plane | UDP path; opposite of TCP-firewall wedge |
| F2 | TLS/cert identity | PSK-over-SSH enough for our use |
| F4 | Delta/dedup | rsync/`sy` territory |
| F5 | S3 | not this tool |
| F6 | bbcp wire compat | different protocol by design |
| C10 | crates.io publish | name `bbx` taken (BBCode); not a goal |

## Version

| Version | Meaning |
|---------|---------|
| `0.x` | Working tool; flags may grow |
| `1.0` | Supported list freezes |
