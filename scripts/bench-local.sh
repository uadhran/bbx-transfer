#!/usr/bin/env bash
# Loopback bench: bbx multi-stream vs single-stream baseline.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$ROOT/target/release/bbx}"
SIZE_MB="${SIZE_MB:-64}"
STREAMS="${STREAMS:-8}"

if [[ ! -x "$BIN" ]]; then
  (cd "$ROOT" && cargo build --release)
fi

IN=$(mktemp)
OUT=$(mktemp)
trap 'rm -f "$IN" "$OUT" "$PORTF"' EXIT
PORTF=$(mktemp)

dd if=/dev/urandom of="$IN" bs=1M count="$SIZE_MB" status=none

run_one() {
  local s=$1
  rm -f "$OUT"
  : >"$PORTF"
  "$BIN" sink -l 127.0.0.1:0 -o "$OUT" -s "$s" -C -E >"$PORTF" &
  local spid=$!
  for _ in $(seq 1 100); do
    grep -q '^PORT ' "$PORTF" 2>/dev/null && break
    sleep 0.02
  done
  local port
  port=$(awk '/^PORT/{print $2; exit}' "$PORTF")
  local t0 t1
  t0=$(date +%s.%N)
  "$BIN" source -a "127.0.0.1:$port" -i "$IN" -s "$s" -C -E >/dev/null
  wait "$spid"
  t1=$(date +%s.%N)
  python3 - "$t0" "$t1" "$SIZE_MB" "$s" <<'PY'
import sys
t0, t1, mb, s = float(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
dt = t1 - t0
rate = mb / dt if dt > 0 else 0
print(f"streams={s:2}  {mb:.0f} MiB in {dt:.3f}s  →  {rate:.1f} MiB/s")
PY
  cmp -s "$IN" "$OUT"
}

echo "bbx local bench (cleartext, no blake3)  file=${SIZE_MB}MiB"
run_one 1
run_one "$STREAMS"
echo "OK"
