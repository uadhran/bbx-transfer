# BBX2 wire protocol

Version **2**. Not compatible with bbcp.

## Roles

| Role | Meaning |
|------|---------|
| **source** | Reads file, sends bytes |
| **sink** | Receives bytes, writes file |

Either side may **listen** or **connect** (forward vs reverse).

## Streams

- Exactly **N** TCP connections (N = 1..64).
- **Dialer** writes `u32 LE stream_id` (0..N-1); **accepter** reorders by id (TCP accept order is not stream order).
- **With `FLAG_CRYPT` / encrypt session:** after the u32, dialer appends a **16-byte SID tag** = first 16 bytes of `BLAKE3 keyed_hash(PSK, "SID\0" ‖ stream_id_le)`. Accepter verifies under the same OOB PSK. Cleartext sessions send only the u32.
- Stream **0** is control (header + range 0 payload).
- Streams **1..N-1** carry only their range payload.
- File size `S` split into N exclusive ranges (sizes differ by ≤1).

## Control header (stream 0)

Little-endian integers.

| Field | Size | Notes |
|-------|------|--------|
| magic | 4 | `BBX2` |
| flags | u32 | bit0 `FLAG_BLAKE3` (1), bit1 `FLAG_CRYPT` (2), bit2 `FLAG_RESUME` (4), bit3 `FLAG_PRESERVE` (8) |
| size | u64 | **full** file bytes |
| streams | u32 | N |
| resume_from | u64 | if `FLAG_RESUME`; start offset (prefix already on sink) |
| salt | 32 | if `FLAG_CRYPT`; random per transfer (clear — needed to derive AEAD key) |
| sealed_meta | var | if `FLAG_CRYPT`: `u32 LE len` ‖ AEAD ciphertext of sensitive fields |
| blake3 | 32 | if `FLAG_BLAKE3` and **not** crypt (clear); under crypt, inside sealed_meta |
| mode | u32 | if `FLAG_PRESERVE` and **not** crypt; under crypt, inside sealed_meta |
| mtime | u64 | if `FLAG_PRESERVE` and **not** crypt; under crypt, inside sealed_meta |

**Sealed meta** (`FLAG_CRYPT`): plaintext concatenation of optional blake3 (32) then optional mode+mtime (4+8). Sealed with ChaCha20-Poly1305 using AEAD key, nonce `stream_id=0 ‖ counter=u64::MAX`, and the same **frame AAD** as payload (below). Empty plaintext still produces a tag-only ciphertext (uniform wire).

Payload covers only `[resume_from, size)`. **Resume always sends the full control header**; only the payload range is shortened.

**Resume:** `FLAG_RESUME` requires `FLAG_BLAKE3`. Sink refuses resume without BLAKE3. Local bytes past `resume_from` are truncated before receive. Prefix content is not re-hashed alone; a post-transfer BLAKE3 failure after resume means the local partial is untrusted — delete the destination and retry a full transfer (do not loop `-A` on a corrupt prefix).

**Fresh sink write:** the sink writes a temporary file beside the destination (same directory), verifies integrity, then renames over the final path. A failed fresh transfer does not truncate/delete a pre-existing destination.

**Recursive pull paths:** remote listing uses `find -print0` (NUL-delimited). Local dest rejects symlink path components so a remote path cannot escape through a local symlink.

## Payload

### Cleartext (`FLAG_CRYPT` clear)

Raw range bytes (no framing). **Policy:** non-loopback cleartext is refused unless `BBX_ALLOW_CLEAR=1`.

### Encrypted (`FLAG_CRYPT` set)

Session **PSK** is 32 bytes, shared **out of band** (SSH agent banner or `-k` / `BBX_KEY`).

**AEAD key** = `BLAKE3 keyed_hash(PSK, salt)` (fresh salt every transfer).

Each stream encrypts independently with **ChaCha20-Poly1305**:

- Nonce (12 bytes) = `stream_id` (u32 LE) ‖ `counter` (u64 LE), counter from 0 per stream (payload); control sealed_meta uses counter `u64::MAX`.
- **AAD** (bound into every payload tag and sealed_meta):  
  `flags_le ‖ size_le ‖ streams_le ‖ resume_from_le ‖ salt` (4+8+4+8+32).
- Frames: `u32 LE ciphertext_len` ‖ ciphertext (includes 16-byte tag).
- Max plaintext per frame: 65536 bytes.

**Wire note:** both ends must match this encrypt framing (SID MAC + salt + sealed meta + AAD). Cleartext framing is unchanged aside from cleartext policy.

## Integrity

`FLAG_BLAKE3`: source hashes file before send; sink re-hashes after write; must match.

Sink local `-c` with peer omitting `FLAG_BLAKE3` is an error. Peer `FLAG_BLAKE3` with local `-C` still verifies (warn).

## SSH agent banner

Listener prints on stdout:

```
PORT <u16>
KEY <64 hex chars>    # only if encrypting
RESUME <u64>          # only if sink -A (existing dest length)
```

| Mode | Data plane |
|------|------------|
| push | remote sink listens; local source connects |
| push `-z` | local source listens; remote sink dials advertise IP |
| pull | local sink listens; remote source dials |
| pull `-z` | remote source listens; local sink connects |

### Listen port range (firewall)

`-Z LO-HI` or env `BBX_PORT_RANGE=LO-HI`: when the listen address uses port **0**, bind the first free port in the inclusive range instead of the OS ephemeral pool. Explicit ports in `-l host:PORT` are unchanged.

### Advertise IP (reverse / pull listen)

Peer dial address host part:

1. `BBX_ADVERTISE` if set (validated host/IP; shell metacharacters rejected)  
2. else local IP on the route toward the SSH peer host  
3. else default-route UDP probe  
4. else `127.0.0.1` (loopback — only useful for same-host tests; warns when remote is set)

### Bind / accept hardening

- `BBX_BIND` — host for ephemeral `cp` listeners (default `0.0.0.0`).
- `BBX_PEER_ALLOW` — optional comma-separated peer IPs; when set, other accept peers are rejected.

## Threat model

- **SSH** authenticates agent start and can carry the session PSK (banner / `BBX_KEY` env).
- **Data plane** with `-e`: payload AEAD; PSK+salt → unique key; SID MAC on accept; control blake3/preserve sealed; AAD binds header fields.
- **Without `-e`**: cleartext TCP; **loopback only** by default (`BBX_ALLOW_CLEAR=1` for trusted non-loopback).
- The session PSK reaches the remote via the banner `KEY` line (listener path) or a
  `BBX_KEY=` environment assignment (dial-out path) — **never** `-k` on argv for remote agent start.
- Salt travels clear on stream 0 (must, to derive). BLAKE3/mode/mtime are **not** clear under `-e` (sealed_meta).

## Liveness

- Data sockets have a read/write timeout; connect and `accept()` are bounded too
  (default 120s, override with `BBX_IO_TIMEOUT_SECS`). A stalled or dead peer fails
  the transfer instead of hanging, and a failing stream aborts its siblings.
- SSH agent wait after transfer is bounded (`BBX_AGENT_WAIT_SECS`, default same as IO timeout);
  timeout kills the local `ssh` child.
- `-x RATE` throttles payload send/recv to about RATE bytes/sec (local only; not on the wire).

## Versioning

Incompatible layouts → new magic (`BBX3`, …).
