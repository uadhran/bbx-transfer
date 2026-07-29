#!/usr/bin/env bash
# Copy local release bbx to a remote host (same binary both ends).
# Usage: ./scripts/install-remote.sh user@host [/remote/path]
set -euo pipefail
REMOTE="${1:?usage: $0 user@host [/remote/path]}"
DEST="${2:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/bbx"
if [[ ! -x $BIN ]]; then
  echo "building release bbx…"
  cargo build --release --manifest-path "$ROOT/Cargo.toml"
fi
if [[ -z $DEST ]]; then
  DEST=$(ssh -o BatchMode=yes "$REMOTE" 'echo $HOME/bin/bbx')
fi
ssh -o BatchMode=yes "$REMOTE" "mkdir -p \"\$(dirname \"$DEST\")\""
scp -o BatchMode=yes -o Compression=no "$BIN" "$REMOTE:$DEST"
ssh -o BatchMode=yes "$REMOTE" "chmod +x \"$DEST\" && \"$DEST\" --help >/dev/null && echo OK $DEST"
echo "export BBX_REMOTE=$DEST"
