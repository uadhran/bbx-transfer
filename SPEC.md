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
- **Dialer** writes `u32 LE stream_id` (0..N-1) as the first bytes on each socket; **accepter** reorders by id (TCP accept order is not stream order).
- Stream **0** is control (header + range 0 payload).
- Streams **1..N-1** carry only their range payload.
- File size `S` split into N exclusive ranges (sizes differ by ≤1).

## Control header (stream 0)

Little-endian integers.

| Field | Size | Notes |
|-------|------|--------|
| magic | 4 | `BBX2` |
| flags | u32 | bit0 `FLAG_BLAKE3` (1), bit1 `FLAG_CRYPT` (2), bit2 `FLAG_RESUME` (4) |
| size | u64 | **full** file bytes |
| streams | u32 | N |
| resume_from | u64 | if `FLAG_RESUME`; start offset (prefix already on sink) |
| blake3 | 32 | if `FLAG_BLAKE3` (hash of **full** file) |

Payload covers only `[resume_from, size)`.

## Payload

### Cleartext (`FLAG_CRYPT` clear)

Raw range bytes (no framing).

### Encrypted (`FLAG_CRYPT` set)

Session **PSK** is 32 random bytes, shared **out of band** (SSH agent banner or `-k`).

Each stream encrypts independently with **ChaCha20-Poly1305**:

- Nonce (12 bytes) = `stream_id` (u32 LE) ‖ `counter` (u64 LE), counter from 0 per stream.
- Frames: `u32 LE ciphertext_len` ‖ ciphertext (includes 16-byte tag).
- Max plaintext per frame: 65536 bytes.

## Integrity

`FLAG_BLAKE3`: source hashes file before send; sink re-hashes after write; must match.

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

1. `BBX_ADVERTISE` if set  
2. else local IP on the route toward the SSH peer host  
3. else default-route UDP probe  
4. else `127.0.0.1` (loopback — only useful for same-host tests)

## Threat model

- **SSH** authenticates agent start and can carry the session PSK (banner / `BBX_KEY` env).
- **Data plane** with `-e`: confidentiality + integrity of payload (AEAD).
- **Without `-e`**: cleartext TCP (trusted network only).
- The session PSK reaches the remote via the banner `KEY` line (listener path) or a
  `BBX_KEY=` environment assignment (dial-out path) — **never** `-k` on argv, so it
  is not exposed to a plain remote `ps`. `-k` remains accepted for manual use.
- BLAKE3 hash still travels cleartext on stream 0 even under `-e` (see F8).

## Liveness

- Data sockets have a read/write timeout; connect and `accept()` are bounded too
  (default 120s, override with `BBX_IO_TIMEOUT_SECS`). A stalled or dead peer fails
  the transfer instead of hanging, and a failing stream aborts its siblings.

## Versioning

Incompatible layouts → new magic (`BBX3`, …).
