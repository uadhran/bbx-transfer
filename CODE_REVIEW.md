# Code review — 2026-08-10

## Scope and confidence

This review covers the current working tree of `bbx` 0.8.0, with emphasis on
the receive path, recursive transfers, and operational safety. It is a static
review supplemented by `cargo test --all-targets` (16 passing tests). It does
not replace adversarial network testing or a cryptography audit.

The repository is deliberately compact and has a well-defined purpose:
multi-stream, large-file transfer between hosts controlled by the operator.
The documentation is candid about its tree-transfer limitations, crypto is
fail-closed on an incorrect key, and the existing loopback tests cover core
single-file behavior.

## Findings

### 1. High — a failed fresh transfer can destroy a pre-existing destination

**Location:** `src/main.rs`, `finish_sink` (open/truncate around line 1698)
and `sink_fail_cleanup` (around line 1538).

**What happens**

For a non-resume transfer, the sink opens the requested destination with
`truncate(true)`. This immediately erases any file already at that path. If a
stream later fails, the checksum differs, or applying preserved metadata fails,
`sink_fail_cleanup` removes the path. The old file cannot be recovered.

**Why it matters**

A transient network failure can turn an attempted overwrite into data loss.
This is particularly risky for automated jobs that write to a stable filename
such as a database dump, artifact, or daily export.

**Recommended fix**

For fresh transfers, write to a unique temporary file in the *destination's
parent directory*. Verify the BLAKE3 hash and apply requested metadata to that
temporary file, then atomically rename it over the destination. On failure,
delete only the temporary file. Keeping the temporary file beside the final
path is important: a rename is atomic only within one filesystem.

Resume needs a separate, explicit policy because it intentionally modifies an
existing partial file. Keep the current truncate-to-trusted-prefix behavior for
that mode, but ensure `-A` is opt-in and document that it owns the destination
while active.

**Prevention**

- Add an integration test: create `dest` with known contents; cause a source
  disconnect or checksum mismatch; assert `dest` is byte-for-byte unchanged.
- Add a corresponding success test that asserts the final file replaces the
  old one only after verification.
- Treat “write then rename” as the standard pattern for every future operation
  that replaces a user file.

### 2. Medium — recursive pull corrupts or skips valid filenames with newlines

**Location:** `src/main.rs`, `remote_list_files` (lines 706–730).

**What happens**

The remote command emits `find` results separated by newlines. The local side
uses `.lines()` and `.trim()` to recover names. Unix permits newline, leading
space, and trailing space in a filename, so a file such as `reports/a\nb.csv`
is interpreted as two paths and a name ending in a space is silently changed.

**Why it matters**

`bbx cp -r` is not correct for all valid source trees. More importantly,
silently altering a pathname can write the wrong local file rather than simply
failing the operation.

**Recommended fix**

Emit NUL-delimited names remotely (`find . -type f -print0`), consume bytes
with `split(|b| *b == 0)`, remove only the literal `./` prefix, and retain
paths as `OsString`/`PathBuf` for local filesystem operations. Convert to a
shell-quoted string only at the remote command boundary. Do not trim filenames.

**Prevention**

- Add recursive integration fixtures with spaces, quotes, leading/trailing
  whitespace, Unicode, and newlines in names.
- State the filename encoding/transport rule in `SPEC.md` or the recursive
  transfer section of `README.md`.
- Prefer byte-oriented path handling at all filesystem and SSH-listing edges.

### 3. Medium — the recursive-pull traversal check does not defend against
local symlink traversal

**Location:** `src/main.rs`, `is_safe_rel` and `cp_pull_tree` (lines 777–903).

**What happens**

The code correctly rejects absolute paths and `..` components from the remote
listing. However, if `LOCAL_DEST/inside` already exists as a symlink, a remote
path `inside/file` passes `is_safe_rel`; `create_dir_all` and the file open then
follow the symlink and can write outside `LOCAL_DEST`.

**Why it matters**

The comment promises protection from a compromised remote. That promise is
incomplete whenever the local destination contains symlinks, including a
symlink planted by another local process or an earlier job.

**Recommended fix**

Choose and document a policy:

1. **Simplest safe policy:** reject any symlink in the destination path during
   recursive pulls.
2. **Stronger Unix policy:** resolve each component using directory file
   descriptors and `O_NOFOLLOW`/`openat`, never following a symlink while
   creating or opening output files.

The first option is appropriate for this tool unless recursive pulls must work
through user-managed symlink trees.

**Prevention**

- Add a test with `LOCAL_DEST/link -> outside-dir`, then attempt to pull
  `link/file`; assert the command fails and no file appears in `outside-dir`.
- Keep path validation and actual path opening in the same security review;
  lexical checks alone cannot make filesystem traversal safe.

### 4. Medium — corrupt resume prefixes are detected late and cannot recover
automatically

**Location:** `src/main.rs`, resume validation around lines 1612–1617 and
post-transfer BLAKE3 verification around lines 1766–1777.

**What happens**

`-A` trusts the length of the destination prefix and transfers only the
suffix. A full-file BLAKE3 comparison detects a corrupted prefix only after
the suffix has been received. Failure cleanup truncates the file back to that
same corrupt prefix, so retrying `-A` repeats the failure indefinitely until
the user manually deletes or repairs the destination.

**Why it matters**

The final integrity check prevents silently accepting bad data, which is good,
but the recovery experience is poor and can waste a full suffix transfer on
large files.

**Recommended fix**

The minimal improvement is to report a precise error telling the user to
remove the partial destination and retry. A stronger design adds resumable
chunk hashes or a sidecar manifest so the sink can identify and re-transfer
the first bad chunk. Do not claim prefix validation until such a mechanism
exists.

**Prevention**

- Add an integration test that corrupts one byte in a partial destination
  before `-A`; assert failure is clear and leaves a defined state.
- Record the intended resume integrity contract in `SPEC.md` and test it for
  every protocol revision.

### 5. Maintainability — orchestration has too many independent parameters

**Location:** `src/main.rs`; for example `cp_push_tree` has 16 parameters and
the `cp_*`, `run_*`, `finish_*`, `send_range`, and `recv_range` helpers have
10–16 parameters.

**What happens**

New flags have been threaded through several parallel code paths. This makes
argument order easy to get wrong and makes it difficult to see which settings
are invariant for a transfer. `cargo clippy --all-targets -- -D warnings`
currently fails primarily for these signatures.

**Recommended fix**

Introduce one small immutable `TransferOptions` struct containing the shared
settings (streams, window, integrity, encryption, resume, progress, JSON,
preserve, and rate). Pass it by reference through orchestration helpers. Keep
role-specific data such as source path, destination path, listener, and key as
separate arguments. This removes most positional-argument risk without a
large module rewrite.

**Prevention**

- Run `cargo fmt --check`, `cargo test --all-targets`, and a chosen Clippy
  policy in CI.
- Add a test matrix for the cross-product that matters: encryption on/off,
  checksum on/off, resume, preserve, and forward/reverse direction.
- Split only when it pays off: `protocol`, `transfer`, and `ssh` are natural
  future boundaries, but a large abstraction layer is not needed now.

## Suggested remediation order

1. Fix destination replacement safety (finding 1) and add the failure test.
2. Decide and implement the symlink policy for recursive pulls (finding 3).
3. Make remote tree listing NUL-delimited and add pathological filename tests
   (finding 2).
4. Improve resume failure messaging, then evaluate chunk manifests only if
   large interrupted transfers are a frequent workload (finding 4).
5. Introduce `TransferOptions` while touching the call graph for the above
   work; do not refactor solely for aesthetics (finding 5).

## Validation performed

| Check | Result |
|---|---|
| `cargo test --all-targets` | Pass — 16 tests |
| `git diff --check` | Pass |
| `cargo clippy --all-targets -- -D warnings` | Fails — 19 warnings promoted to errors, mostly `too_many_arguments`, plus one nested `if` and a `contains` suggestion |

No source changes were made as part of this review. The working tree already
contained an unrelated modification to `src/main.rs`; it was left untouched.
