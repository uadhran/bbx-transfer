# BBX2 wire protocol

Version **2**. Not compatible with bbcp or BBX1.

## Roles

| Role | Meaning |
|------|---------|
| **source** | Reads file, sends bytes |
| **sink** | Receives bytes, writes file |

Either side may **listen** or **connect** (forward vs reverse).

## Streams

- Exactly **N** TCP connections (N = 1..64), negotiated in the control header.
- Connection **0** is the control stream (header + file range 0).
- Connections **1..N-1** carry only payload for their range.
- File size `S` is split into N exclusive ranges `[start, end)` (sizes differ by at most 1 byte).

## Control header (stream 0, before payload)

All multi-byte integers are **little-endian**.

| Field | Size | Notes |
|-------|------|--------|
| magic | 4 | `BBX2` (`0x42 0x42 0x58 0x32`) |
| flags | u32 | bit0 = `FLAG_BLAKE3` (1) |
| size | u64 | file size in bytes |
| streams | u32 | N |
| blake3 | 32 | only if `FLAG_BLAKE3`; digest of full file |

Then stream 0 immediately sends `range[0]` raw bytes. Other streams send only their range bytes (no per-chunk framing).

## Integrity

When `FLAG_BLAKE3` is set:

1. Source hashes the file (BLAKE3) before send and includes the 32-byte digest.
2. Sink writes the file, then hashes the result and **must** match or abort.

## SSH orchestration (`bbx cp`)

Out of band (not on the data sockets):

- `BBX_REMOTE` — path to `bbx` on the remote host.
- `BBX_ADVERTISE` — address remote should dial for reverse/pull (default: guessed local IP).
- Listener side prints `PORT <u16>\n` on stdout once bound.

| Mode | Data plane |
|------|------------|
| push | remote sink listens; local source connects |
| push `-z` | local source listens; remote sink connects to `BBX_ADVERTISE` |
| pull | local sink listens; remote source connects to `BBX_ADVERTISE` |
| pull `-z` | remote source listens; local sink connects |

**Threat model:** data plane is **cleartext TCP**. Use a trusted network or tunnel. Auth is SSH for agent start only.

## Versioning

Bump magic (`BBX3`, …) for breaking changes. Never reuse `BBX2` for incompatible layouts.
