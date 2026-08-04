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

# Reject shell metacharacters so DEST never breaks out of remote quoting.
# Allows absolute/relative paths with alnum, . _ - /
valid_dest() {
  [[ "$1" =~ ^[A-Za-z0-9._/-]+$ ]] && [[ "$1" != *..* ]]
}

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

if [[ -z "${DEST}" ]]; then
  DEST=$(ssh -o BatchMode=yes "$REMOTE" 'echo $HOME/bin/bbx')
fi

if ! valid_dest "$DEST"; then
  echo "install-remote: refusing unsafe DEST: $DEST" >&2
  echo "  allow only [A-Za-z0-9._/-] (no spaces, quotes, or shell metacharacters)" >&2
  exit 1
fi

# Quote for remote shell (bash printf %q); embed without re-wrapping.
DEST_Q=$(printf '%q' "$DEST")
ssh -o BatchMode=yes "$REMOTE" "mkdir -p -- \$(dirname -- ${DEST_Q})"
scp -o BatchMode=yes -o Compression=no "$BIN" "${REMOTE}:${DEST}"
ssh -o BatchMode=yes "$REMOTE" "chmod +x -- ${DEST_Q} && ${DEST_Q} help >/dev/null 2>&1 && echo OK ${DEST_Q}"
echo "export BBX_REMOTE=${DEST_Q}"
echo "local binary: $BIN"
