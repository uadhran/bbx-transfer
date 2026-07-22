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
- Connection **0** is control (header + range 0 payload).
- Connections **1..N-1** carry only their range payload.
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
| push `-z` | local source listens; remote sink dials `BBX_ADVERTISE` (+ `-k`) |
| pull | local sink listens; remote source dials |
| pull `-z` | remote source listens; local sink connects |

## Threat model

- **SSH** authenticates agent start and can carry the session PSK (banner / argv).
- **Data plane** with `-e`: confidentiality + integrity of payload (AEAD).
- **Without `-e`**: cleartext TCP (trusted network only).
- PSK on process argv (`-k`) is visible to local `ps` — acceptable for lab; prefer banner KEY on listener path.

## Versioning

Incompatible layouts → new magic (`BBX3`, …).
