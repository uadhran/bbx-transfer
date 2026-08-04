# bbx — simple commands

**Rule:** same **0.8.0+** binary on both machines (encrypt wire changed). Use **musl** build for remotes.

```bash
# once per shell (point at your local build or install path)
export BBX=./target/x86_64-unknown-linux-musl/release/bbx
# path to bbx *on the remote host*
export BBX_REMOTE=/path/to/bbx
```

---

## Install remote (once)

```bash
./scripts/install-remote.sh user@host /path/to/bbx
# example: ./scripts/install-remote.sh user@host ~/bin/bbx
```

---

## Push (local → remote)

```bash
$BBX cp -s 8 -P 1 -C -E \
  /local/path/file \
  user@host:/remote/path/file
```

## Pull (remote → local)

```bash
$BBX cp -s 8 -P 1 -C -E \
  user@host:/remote/path/file \
  /local/path/file
```

---

## Flags you actually use

| Flag | Meaning |
|------|---------|
| `-s 8` | 8 streams (good default) |
| `-P 1` | progress every 1s |
| `-C -E` | no hash / no encrypt (fast on trusted LAN; non-loopback needs `BBX_ALLOW_CLEAR=1`) |
| *(omit -C -E)* | encrypt + BLAKE3 (default for `cp`) |
| `-A` | resume partial dest |
| `-r` | whole directory (slow if many tiny files) |
| `-Z 50000-50063` | firewall port range |

---

## Example: set host + dirs once

```bash
export BBX=./target/x86_64-unknown-linux-musl/release/bbx
export BBX_REMOTE=~/bin/bbx
HOST=user@host
RDIR=/remote/data
LDIR=/local/data

# pull one file
$BBX cp -s 8 -P 1 -C -E \
  "$HOST:$RDIR/example.csv.zst" \
  "$LDIR/example.csv.zst"

# push one file
$BBX cp -s 8 -P 1 -C -E \
  "$LDIR/example.clean.csv" \
  "$HOST:$RDIR/example.clean.csv"
```

---

## Optional alias (add to `~/.bashrc`)

```bash
alias bbx='/path/to/bbx'   # local binary
export BBX_REMOTE=/path/to/bbx   # remote binary path
```

Then: `bbx cp -s 8 -P 1 -C -E local user@host:remote`

---

## Don’t

- Mix **0.7** and **0.8** encrypt peers (wire break)  
- Use `-r` for thousands of tiny files → use **rsync**  
- Put only a directory as dest for a single file → use **full file path**  
