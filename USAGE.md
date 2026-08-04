# bbx — simple commands

**Rule:** same **0.8.0+** binary on both machines (encrypt wire changed). Use **musl** build for remotes.

```bash
# once per shell
export BBX=/home/utkarsh/projects/bbx/target/x86_64-unknown-linux-musl/release/bbx
# path to bbx *on the remote host*
export BBX_REMOTE=/path/to/bbx
```

---

## Install remote (once)

```bash
./scripts/install-remote.sh user@host /path/to/bbx
# example: ./scripts/install-remote.sh support@172.18.0.162 /home/support/bbx
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
| `-C -E` | no hash / no encrypt (fast on trusted LAN) |
| *(omit -C -E)* | encrypt + BLAKE3 (default for `cp`) |
| `-A` | resume partial dest |
| `-r` | whole directory (slow if many tiny files) |
| `-Z 50000-50063` | firewall port range |

---

## Your common paths (edit as needed)

```bash
export BBX=/home/utkarsh/projects/bbx/target/x86_64-unknown-linux-musl/release/bbx
export BBX_REMOTE=/home/storage/shbm-team/shbm-common/bbx
HOST=shbm-common@172.18.0.140
RDIR=/home/storage/shbm-team/shbm-common/TAIFEX/reports/shubm/2026/option_chains_T1_greeks_fri
LDIR=/home/utkarsh/mine/scripts/shbm-common@140/t1_work/DATA/2026/option_chains_T1_greeks_fri

# pull one file
$BBX cp -s 8 -P 1 -C -E \
  "$HOST:$RDIR/option_chain_greeks_20260612_T1_20260611.csv.zst" \
  "$LDIR/option_chain_greeks_20260612_T1_20260611.csv.zst"

# push one file
$BBX cp -s 8 -P 1 -C -E \
  /home/utkarsh/mine/scripts/shbm-common@140/t1_work/DATA/tmp/file.clean.csv \
  "$HOST:$RDIR/file.clean.csv"
```

---

## Optional alias (add to `~/.bashrc`)

```bash
alias bbx='/home/utkarsh/projects/bbx/target/x86_64-unknown-linux-musl/release/bbx'
export BBX_REMOTE=/home/storage/shbm-team/shbm-common/bbx   # change per host
```

Then: `bbx cp -s 8 -P 1 -C -E local user@host:remote`

---

## Don’t

- Mix **0.6** and **0.7** binaries  
- Use `-r` for thousands of tiny files → use **rsync**  
- Put only a directory as dest for a single file → use **full file path**  
