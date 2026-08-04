# bbx — multi-stream bulk copy

> GitHub: **[uadhran/bbx-transfer](https://github.com/uadhran/bbx-transfer)** · CLI binary: **`bbx`**

Internal-first **TCP multi-stream** file copy (bbcp-class), open **BBX2** protocol, optional **BLAKE3** + **ChaCha20-Poly1305**.

**Not** rsync (no delta/sync). **Not** QUIC. **Not** on crates.io (binary name `bbx` is unrelated to the BBCode crate).

Same `bbx` version on **both** hosts.

## Scope

| Use bbx when | Use something else when |
|--------------|-------------------------|
| Large files over high-latency / multi-stream TCP | Tree sync / incremental → rsync, `sy` |
| UDP is blocked (QUIC tools fail) | You need object storage → rclone/S3 tools |
| You control both ends and can open a TCP port range | Single-stream scp is already enough |

## Install (both ends)

```sh
cargo build --release
# local: target/release/bbx
# remote: same binary
./scripts/install-remote.sh user@host /home/user/bin/bbx
export BBX_REMOTE=/home/user/bin/bbx
```

Or copy by hand: `scp target/release/bbx user@host:~/bin/bbx`.

## Quick remote push / pull

**Copy-paste recipes:** **[USAGE.md](USAGE.md)**

```sh
export BBX_REMOTE=/path/to/bbx   # on remote
bbx cp -s 8 -P 1 -C -E big.bin user@host:~/big.bin   # push
bbx cp -s 8 -P 1 -C -E user@host:~/big.bin ./big.bin  # pull
# defaults without -C -E: BLAKE3 + encrypt on
```

## Firewall: fixed port range

Data plane needs N TCP connections (streams). Ephemeral ports are painful behind strict firewalls.

```sh
# open 50000-50063 on the listening side, then:
bbx cp -s 8 -Z 50000-50063 big.bin user@host:~/big.bin
# or:
export BBX_PORT_RANGE=50000-50063
```

`-Z` / `BBX_PORT_RANGE` applies to the **listener** (remote on forward push, local on pull / `-z`).

## Reverse dial

When the remote must dial you (`-z` push, or default pull):

```sh
export BBX_ADVERTISE=203.0.113.10   # if auto-detect is wrong
bbx cp -z -s 8 big.bin user@host:~/big.bin
```

Auto-detect order: `BBX_ADVERTISE` → route toward remote host → default-route UDP → else `127.0.0.1` (will fail for real remotes).

## Flags

| Flag | Meaning |
|------|---------|
| `-s N` | streams (default 4, max 64) |
| `-w SIZE` | socket buffer hint |
| `-P SEC` | progress interval (source and sink, including pull) |
| `-c` / `-C` | BLAKE3 on/off (`cp` default on) |
| `-e` / `-E` | encrypt on/off (`cp` default on) |
| `-A` | resume partial dest |
| `-R N` | source: resume from byte offset N |
| `-J` | JSON progress on stdout |
| `-r` | recursive dirs (**one session per file**; files ≤1 MiB use **1 stream**) |
| `--preserve` / `-p` | preserve mode + mtime |
| `-x RATE` | throttle bytes/sec (e.g. `10M`) |
| `-z` | reverse dial |
| `-Z LO-HI` | listen port range |
| `-k HEX` | session key (manual; remote prefers `BBX_KEY` env) |

Env: `BBX_REMOTE`, `BBX_ADVERTISE`, `BBX_KEY`, `BBX_PORT_RANGE`, `BBX_IO_TIMEOUT_SECS` (default 120), `BBX_BIND` (listen host), `BBX_PEER_ALLOW` (comma IPs), `BBX_AGENT_WAIT_SECS` (SSH agent wait), `BBX_ALLOW_CLEAR=1` (permit non-loopback cleartext).

`cp` specs: `user@host:path`, `host:path`, or IPv6 `user@[2001:db8::1]:path` / `[::1]:path`.

## Reliability

- Connect timeout 30s; accept / read / write timeout `BBX_IO_TIMEOUT_SECS` (default 120s).
- One dead stream aborts the transfer.
- Failed transfer kills the remote SSH agent process.

## Security

Session key over SSH (`KEY` banner or `BBX_KEY` env — not `-k` on remote argv). Data plane with `-e`: AEAD (PSK+salt), stream-id MAC, sealed BLAKE3/preserve meta, AAD-bound payload tags (both ends must match). Cleartext (`-E`) is **loopback-only** unless `BBX_ALLOW_CLEAR=1`. Resume (`-A`) requires BLAKE3 (`-c`). Optional: `BBX_BIND`, `BBX_PEER_ALLOW`. See [SPEC.md](SPEC.md#threat-model).

## Limitations

- `-r` is sequential per file (batch remote `mkdir`; small files force 1 stream) — not a tiny-file / metadata tool.
- **0.7.0+ both ends:** multi-stream sockets carry a stream-id prefix (not compatible with 0.6.x peers).
- **0.8.0+ both ends for encrypt:** PSK+salt AEAD, stream-id MAC, sealed control meta, AAD-bound frames (not compatible with 0.7.x encrypt peers).
- **Encrypted wire:** control header includes 32-byte salt — peers without salt support will not interoperate.

## Docs

- [SPEC.md](SPEC.md) — wire protocol  
- [ROADMAP.md](ROADMAP.md) — open work  
- [CONTRIBUTING.md](CONTRIBUTING.md)  

## License

MIT
