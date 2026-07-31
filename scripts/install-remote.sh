#!/usr/bin/env bash
# Copy portable bbx to a remote host (same binary both ends).
# Prefers musl static build so newer host glibc does not break older remotes.
# Usage: ./scripts/install-remote.sh user@host [/remote/path]
set -euo pipefail
REMOTE="${1:?usage: $0 user@host [/remote/path]}"
DEST="${2:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MUSL="$ROOT/target/x86_64-unknown-linux-musl/release/bbx"
GNU="$ROOT/target/release/bbx"

if [[ -x $MUSL ]]; then
  BIN=$MUSL
elif rustup target list --installed 2>/dev/null | grep -q 'x86_64-unknown-linux-musl'; then
  echo "building musl release bbx (portable)…"
  cargo build --release --target x86_64-unknown-linux-musl --manifest-path "$ROOT/Cargo.toml"
  BIN=$MUSL
elif [[ -x $GNU ]]; then
  echo "warn: using glibc binary; may fail on older remotes (need GLIBC from build host)"
  BIN=$GNU
else
  echo "building release bbx…"
  cargo build --release --manifest-path "$ROOT/Cargo.toml"
  BIN=$GNU
fi

if [[ -z $DEST ]]; then
  DEST=$(ssh -o BatchMode=yes "$REMOTE" 'echo $HOME/bin/bbx')
fi
ssh -o BatchMode=yes "$REMOTE" "mkdir -p \"\$(dirname \"$DEST\")\""
scp -o BatchMode=yes -o Compression=no "$BIN" "$REMOTE:$DEST"
ssh -o BatchMode=yes "$REMOTE" "chmod +x \"$DEST\" && \"$DEST\" help >/dev/null 2>&1 && echo OK \"$DEST\""
echo "export BBX_REMOTE=$DEST"
echo "local binary: $BIN"
