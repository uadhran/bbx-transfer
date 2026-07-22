# bbx

Multi-stream bulk file copy. **Open BBX2 protocol**, BLAKE3 verify, push/pull/reverse.

Not wire-compatible with [bbcp](https://www.slac.stanford.edu/~abh/bbcp/).

## Why bbx (vs bbcp)

| | bbcp | bbx |
|--|------|-----|
| Protocol | tribal / C++ only | [SPEC.md](SPEC.md) |
| Integrity | optional legacy hashes | **BLAKE3 default** on `cp` |
| Direction | mostly push-shaped | **push + pull** |
| NAT | obscure `-z` | **`-z` reverse** + `BBX_ADVERTISE` |
| Build | multi-OS makefile | `cargo build --release` |

## Install

```sh
cargo build --release
# binary: target/release/bbx
# copy same binary to remote (or cargo build there)
```

## Usage

### Local (no ssh)

```sh
bbx sink -l 127.0.0.1:0 -o /tmp/out -s 4 -c   # prints PORT n
bbx source -a 127.0.0.1:n -i /tmp/in -s 4 -c -P 1
```

### Push (local → remote)

Needs **inbound TCP to remote** data port (or use `-z`).

```sh
export BBX_REMOTE=/path/to/bbx   # on remote
bbx cp -s 8 -P 5 big.bin user@host:~/big.bin
```

### Push reverse (`-z`) — remote dials you

Remote must reach your IP (`BBX_ADVERTISE` if guess is wrong).

```sh
export BBX_REMOTE=/path/to/bbx
export BBX_ADVERTISE=10.0.0.5    # your address as seen by remote
bbx cp -z -s 8 -P 5 big.bin user@host:~/big.bin
```

### Pull (remote → local)

```sh
export BBX_REMOTE=/path/to/bbx
export BBX_ADVERTISE=10.0.0.5
bbx cp -s 8 -P 5 user@host:~/big.bin ./big.bin
```

### Flags

| Flag | Meaning |
|------|---------|
| `-s N` | streams (default 4) |
| `-w SIZE` | socket buffer hint (`4M`, …) |
| `-P SEC` | progress refresh |
| `-c` / `-C` | BLAKE3 on / off (`cp` defaults **on**) |
| `-z` | reverse dial direction |

## Security

Data path is **plain TCP**. SSH only starts the remote agent. Use trusted LAN/VPN or wrap later (P1: encrypt).

## Status (roadmap)

- [x] **P0** multi-stream, push/pull, reverse, BLAKE3, SPEC, CI  
- [ ] **P1** encrypted data plane / QUIC, `cargo install` polish  
- [ ] **P2** resume, JSON progress, benches  

## License

MIT
