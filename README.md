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
| `-P SEC` | progress (`SEC`>0 enables; TTY uses indicatif bar; `-J` uses JSON every `SEC`s) |
| `-c` / `-C` | BLAKE3 on/off (`cp` default on) |
| `-e` / `-E` | encrypt on/off (`cp` default on) |
| `-A` | resume partial dest |
| `-R N` | source: resume from byte offset N |
| `-J` | JSON progress on stdout |
| `-r` | recursive dirs (**one session per file**; files ≤1 MiB use **1 stream**). Pull sizes come from GNU find; without `-printf`, one stream per file. |
| `--preserve` / `-p` | preserve mode + mtime |
| `-x RATE` | throttle bytes/sec (e.g. `10M`) |
| `-z` | reverse dial |
| `-Z LO-HI` | listen port range |
| `-k HEX` | session key for manual sink/source. Prefer `BBX_KEY`: `-k` is on the local argv. |
| `--key-stdin` | sink/source only. Read one 64-hex line from stdin. `bbx cp` places this after `source` or `sink` and writes the key on ssh stdin. |

Env: `BBX_REMOTE`, `BBX_ADVERTISE`, `BBX_KEY`, `BBX_PORT_RANGE`, `BBX_IO_TIMEOUT_SECS` (default 120), `BBX_BIND` (listen host), `BBX_PEER_ALLOW` (comma-separated IPs; only `any` allows every peer; empty is ignored), `BBX_PEER_DEFAULT=ssh` (allow only the `SSH_CONNECTION` client), `BBX_AGENT_WAIT_SECS` (SSH agent wait), `BBX_ALLOW_CLEAR=1` (permit non-loopback cleartext).

`bbx cp` sends `BBX_PEER_DEFAULT=ssh` to a remote listener unless `BBX_PEER_ALLOW=any`. When `bbx cp` listens locally it allows the resolved addresses of the remote host. If that name does not resolve, an encrypted transfer warns and allows any peer, and a cleartext transfer stops. A rejected peer is told to set `BBX_PEER_ALLOW=any` or to add that address.

`cp` specs: `user@host:path`, `host:path`, or IPv6 `user@[2001:db8::1]:path` / `[::1]:path`.

## Reliability

- Connect timeout 30s; accept / read / write timeout `BBX_IO_TIMEOUT_SECS` (default 120s).
- A failed stream handshake is dropped (5s read timeout). 32 rejections stop the listener. The accept deadline stays `BBX_IO_TIMEOUT_SECS`.
- `cp` pull and `cp` push `-z`: if the remote SSH child has exited while this side is still accepting, accepting stops and the error includes the last rejection.
- One dead stream aborts the transfer.
- Failed transfer kills the remote SSH agent process.

## Security

Session key over SSH: the listener path still uses the `KEY` banner. Dial-out (encrypted pull, push `-z`, and pull `-z` with a fixed key) writes one 64-hex line on the agent stdin. The remote command does not contain `BBX_KEY=` or `-k`. Manual sink and source still accept `BBX_KEY`. Data plane with `-e`: AEAD (PSK+salt), stream-id MAC, sealed BLAKE3/preserve meta, AAD-bound payload tags (both ends must match). Cleartext (`-E`) is **loopback-only** unless `BBX_ALLOW_CLEAR=1`. Resume (`-A`) requires BLAKE3 (`-c`). Optional: `BBX_BIND`, `BBX_PEER_ALLOW`, `BBX_PEER_DEFAULT=ssh`. See [SPEC.md](SPEC.md#threat-model).

## Limitations

- `-r` is sequential per file (batch remote `mkdir`; small files force 1 stream) — not a tiny-file / metadata tool.
- **1.0.0+ both ends for encrypt:** stream-id prefix + PSK/salt AEAD, stream-id MAC, sealed control meta, AAD-bound frames. Fresh receive is temp-then-rename; `-r` pull uses NUL listing; symlink path components under dest are refused. Implementation is a library crate under `src/`.
- **1.0.1:** `-P` on a TTY uses an indicatif progress bar (`-J` JSON unchanged).
- **1.0.2:** on 1.0.2, bbx cp listeners reject a peer whose address differs from the SSH host/client address; set BBX_PEER_ALLOW to that address or to "any".
- **1.1.0:** `-V` and `--version` print `bbx 1.1.0`. On 1.1.0, encrypted `bbx cp` pull, push `-z`, and pull `-z` with a fixed key require a 1.1.0 remote. The key is no longer passed as `BBX_KEY=` in the ssh command.
- **1.1.1:** `-V` and `--version` print `bbx 1.1.1`. Test-only fix; 1.1.0 and 1.1.1 binaries interoperate.
- **1.1.2:** `-r` pull reads each file's size with GNU `find -printf`. Files of 1 MiB or less use 1 stream; larger files use `-s`. If the remote find has no `-printf`, bbx warns once and uses 1 stream per file.
- **Encrypted wire:** control header includes 32-byte salt — peers without this framing will not interoperate.

## Docs

- [SPEC.md](SPEC.md) — wire protocol  
- [ROADMAP.md](ROADMAP.md) — open work  
- [CONTRIBUTING.md](CONTRIBUTING.md)  

## License

MIT
