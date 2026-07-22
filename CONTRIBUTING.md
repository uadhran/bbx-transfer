# Contributing

## Dev

```sh
cargo test
cargo build --release
```

## Good first issues

- Protocol edge cases (empty file, 1 stream, max streams)
- Better `BBX_ADVERTISE` discovery
- Progress on sink during pull
- Windows support (`FileExt` / sockbuf)

## Protocol changes

Update [SPEC.md](SPEC.md) in the same PR. Breaking changes need a new magic (`BBX3`).

## Scope

See README roadmap. P1 (encryption/QUIC) and P2 (resume/JSON) are open for design notes before large code.
