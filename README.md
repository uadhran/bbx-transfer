# bbx

Multi-stream bulk file copy in Rust.

**BBX2** open protocol · **BLAKE3** verify · **ChaCha20-Poly1305** data plane · push/pull/reverse.

Not wire-compatible with [bbcp](https://www.slac.stanford.edu/~abh/bbcp/).

## Install

```sh
# from clone
cargo install --path .

# after crates.io publish
# cargo install bbx
```

Binary: `~/.cargo/bin/bbx` (or `target/release/bbx`). **Same version on both hosts.**

## Quick remote push

```sh
export BBX_REMOTE=/path/to/bbx   # on remote
bbx cp -s 8 -P 5 big.bin user@host:~/big.bin
# defaults: BLAKE3 + encrypt on
```

Disable: `-C` (no checksum), `-E` (cleartext).

## Modes

| | Command |
|--|---------|
| Push | `bbx cp local user@host:path` |
| Pull | `bbx cp user@host:path local` |
| Reverse | add `-z` + `BBX_ADVERTISE=your.ip` |

## Flags

| Flag | Meaning |
|------|---------|
| `-s N` | streams (default 4) |
| `-w SIZE` | socket buffer hint |
| `-P SEC` | progress |
| `-c` / `-C` | BLAKE3 on/off (`cp` default on) |
| `-e` / `-E` | encrypt on/off (`cp` default on) |
| `-z` | reverse dial |
| `-k HEX` | session key (agents; usually automatic) |

## Why not bbcp

| | bbcp | bbx |
|--|------|-----|
| Protocol | closed C++ | [SPEC.md](SPEC.md) |
| Data plane | often cleartext | **AEAD default** |
| Direction | awkward | push + pull + `-z` |
| Build | makefile zoo | `cargo install` |

## Status

- [x] P0 multi-stream, push/pull, reverse, BLAKE3, SPEC, CI  
- [x] **P1** encrypted data plane, install metadata  
- [ ] P2 resume, JSON progress, benches  

## Security

Session key is established over SSH (banner or `-k`). Data sockets use ChaCha20-Poly1305 when `-e`. See SPEC threat model.

## License

MIT
