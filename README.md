# bbx — multi-stream encrypted bulk copy

> GitHub: **[uadhran/bbx-transfer](https://github.com/uadhran/bbx-transfer)** · CLI binary: **`bbx`**  
> Keywords: `rust` `file-transfer` `scp` `bbcp` `multi-stream` `blake3` `chacha20`

Fast parallel file copy over many TCP streams (bbcp-class), with an **open BBX2 protocol**, **BLAKE3** verify, and **ChaCha20-Poly1305** on the data plane.

Not wire-compatible with classic [bbcp](https://www.slac.stanford.edu/~abh/bbcp/).

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
| `-P SEC` | progress interval |
| `-c` / `-C` | BLAKE3 on/off (`cp` default on) |
| `-e` / `-E` | encrypt on/off (`cp` default on) |
| `-A` | **resume** partial destination |
| `-R N` | source: resume from byte offset N |
| `-J` | **JSON** progress lines on stdout |
| `-r` | **recursive** directory trees (one session per file) |
| `-z` | reverse dial |
| `-k HEX` | session key (agents; usually automatic) |

### Resume

```sh
# if dest already has a prefix (e.g. failed mid-copy):
bbx cp -A -s 8 big.bin user@host:~/big.bin
```

### JSON progress

```sh
bbx source -a 127.0.0.1:PORT -i file -J -P 1
# {"event":"progress","bytes":…,"total":…,"rate_mbps":…}
# {"event":"done",…}
```

## Why not bbcp

| | bbcp | bbx |
|--|------|-----|
| Protocol | closed C++ | [SPEC.md](SPEC.md) |
| Data plane | often cleartext | **AEAD default** |
| Direction | awkward | push + pull + `-z` |
| Build | makefile zoo | `cargo install` |

## Status / roadmap

**Shipped P0–P3.** Open work and future ideas live in **[ROADMAP.md](ROADMAP.md)** (contributor-friendly: C1–C10 open, F1–F8 future).

```sh
./scripts/bench-local.sh   # loopback multi-stream timing
bbx cp -r ./mydir user@host:~/mydir
```

## Security

Session key is established over SSH (banner or `-k`). Data sockets use ChaCha20-Poly1305 when `-e`. See SPEC threat model.

## License

MIT
