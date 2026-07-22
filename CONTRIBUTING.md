# Contributing

## Dev

```sh
cargo test
cargo build --release
./scripts/bench-local.sh   # optional
```

## Where to start

1. Read **[ROADMAP.md](ROADMAP.md)** — shipped vs open vs future.  
2. Pick an **open** item (C1–C10), not a “future/hard” item, unless you propose a design first.  
3. Open a PR against `master`.  
4. Wire changes → update **[SPEC.md](SPEC.md)** in the same PR.

## Rules of the road

- **One feature per PR** when possible.  
- **Acceptance**: add or extend a test / CI smoke for the behavior.  
- **No drive-by scope**: don’t claim bbcp parity or 1.0 without discussion.  
- Breaking protocol → new magic (`BBX3`), never silent layout changes to `BBX2`.

## Good first issues

See ROADMAP **Open for contributors**. File a GitHub issue with the roadmap ID (e.g. `C2`) if none exists yet.
