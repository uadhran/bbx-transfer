//! Recursive (-r) tree walk, remote listing, and per-file tree orchestration.

use crate::cli::TransferOpts;
use crate::commands::streams_for_file;
use crate::cp::{cp_pull_forward, cp_pull_reverse, cp_push_forward, cp_push_reverse};
use crate::ssh::shell_quote;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn walk_local_files(root: &std::path::Path) -> Result<Vec<(std::path::PathBuf, String)>, String> {
    let root = root
        .canonicalize()
        .map_err(|e| format!("src: {e}"))?;
    if !root.is_dir() {
        return Err(" -r needs a source directory".into());
    }
    let mut out = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    walk_local_rec(&root, &root, &mut out, &mut skipped)?;
    out.sort_by(|a, b| a.1.cmp(&b.1));
    warn_skipped_symlinks(&skipped);
    Ok(out)
}

/// Symlinks are not followed by `-r` (a copy of the tree, not the link targets).
/// Silently dropping them hides an incomplete transfer, so warn with a capped list.
pub(crate) fn warn_skipped_symlinks(skipped: &[String]) {
    if skipped.is_empty() {
        return;
    }
    let mut shown: Vec<&String> = skipped.iter().collect();
    shown.sort();
    eprintln!(
        "bbx: warning: skipped {} symlink(s) under source (not followed by -r):",
        skipped.len()
    );
    const MAX_SHOWN: usize = 10;
    for rel in shown.iter().take(MAX_SHOWN) {
        eprintln!("bbx:   {rel}");
    }
    if shown.len() > MAX_SHOWN {
        eprintln!("bbx:   … and {} more", shown.len() - MAX_SHOWN);
    }
}

pub(crate) fn walk_local_rec(
    base: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<(std::path::PathBuf, String)>,
    skipped: &mut Vec<String>,
) -> Result<(), String> {
    for ent in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let ent = ent.map_err(|e| e.to_string())?;
        let path = ent.path();
        let ft = ent.file_type().map_err(|e| e.to_string())?;
        let rel = |p: &std::path::Path| {
            p.strip_prefix(base)
                .map(|r| r.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| p.to_string_lossy().replace('\\', "/"))
        };
        if ft.is_dir() {
            walk_local_rec(base, &path, out, skipped)?;
        } else if ft.is_file() {
            out.push((path.clone(), rel(&path)));
        } else if ft.is_symlink() {
            // Not followed: record so the user is warned rather than silently dropping it.
            skipped.push(rel(&path));
        }
    }
    Ok(())
}

/// Parse `find -print0` stdout into relative paths (no trim; strip leading `./` only).
pub(crate) fn parse_find_print0(stdout: &[u8]) -> Vec<String> {
    let mut files = Vec::new();
    for part in stdout.split(|&b| b == 0) {
        if part.is_empty() {
            continue;
        }
        let mut s = String::from_utf8_lossy(part).into_owned();
        if let Some(rest) = s.strip_prefix("./") {
            s = rest.to_string();
        }
        if s.is_empty() {
            continue;
        }
        files.push(s);
    }
    files.sort();
    files
}

pub(crate) fn remote_list_files(remote: &str, rpath: &str) -> Result<Vec<String>, String> {
    // NUL-delimited so names may contain newlines/spaces; do not trim components.
    let out = Command::new("ssh")
        .arg(remote)
        .arg(format!(
            "cd {} && find . -type f -print0",
            shell_quote(rpath)
        ))
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("ssh find: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "remote find failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(parse_find_print0(&out.stdout))
}

/// One SSH round-trip for many parents (tree push).
pub(crate) fn ssh_mkdir_p_many<'a>(
    remote: &str,
    dirs: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    let mut q = String::from("mkdir -p");
    let mut n = 0usize;
    for d in dirs {
        if d.is_empty() {
            continue;
        }
        q.push(' ');
        q.push_str(&shell_quote(d));
        n += 1;
    }
    if n == 0 {
        return Ok(());
    }
    let st = Command::new("ssh")
        .arg(remote)
        .arg(q)
        .stdin(Stdio::inherit())
        .status()
        .map_err(|e| format!("ssh mkdir: {e}"))?;
    if !st.success() {
        return Err("mkdir -p failed".into());
    }
    Ok(())
}

pub(crate) fn join_remote(base: &str, rel: &str) -> String {
    let base = base.trim_end_matches('/');
    if rel.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{rel}")
    }
}

pub(crate) fn parent_posix(path: &str) -> Option<String> {
    let path = path.trim_end_matches('/');
    path.rfind('/').map(|i| path[..i].to_string())
}

/// A relative path from a remote `find` is untrusted: reject anything that is
/// absolute or contains a `..` component so a compromised remote can't make us
/// write outside the local destination directory (path traversal).
pub fn is_safe_rel(rel: &str) -> bool {
    use std::path::Component;
    if rel.is_empty() {
        return false;
    }
    let p = Path::new(rel);
    if p.is_absolute() {
        return false;
    }
    p.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// Reject symlink components under `dest_root/rel` so recursive pull cannot
/// follow a local symlink and write outside the destination tree.
pub(crate) fn dest_path_has_symlink(dest_root: &Path, rel: &str) -> Result<bool, String> {
    use std::path::Component;
    let mut cur = dest_root.to_path_buf();
    // If dest root itself is a symlink, reject (writes escape the named tree).
    if cur
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Ok(true);
    }
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(name) => {
                cur.push(name);
                match cur.symlink_metadata() {
                    Ok(m) if m.file_type().is_symlink() => return Ok(true),
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        // Remaining path does not exist yet — safe so far.
                        break;
                    }
                    Err(e) => return Err(e.to_string()),
                }
            }
            Component::CurDir => {}
            _ => return Ok(true), // unexpected after is_safe_rel
        }
    }
    Ok(false)
}

/// Sequential multi-file push (one BBX2 session per file). Clear, correct, not fancy.
pub(crate) fn cp_push_tree(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_src: &str,
    opts: TransferOpts,
    rev: bool,
    port_range: Option<(u16, u16)>,
    fixed_key: Option<[u8; 32]>,
) -> Result<(), String> {
    let root = Path::new(local_src);
    let files = walk_local_files(root)?;
    if files.is_empty() {
        return Err("no files under source directory".into());
    }
    // Batch mkdir parents in one SSH (avoid per-file SSH storms).
    let mut parents: Vec<String> = Vec::new();
    parents.push(rpath.trim_end_matches('/').to_string());
    for (_, rel) in &files {
        let remote_file = join_remote(rpath, rel);
        if let Some(parent) = parent_posix(&remote_file) {
            if !parents.iter().any(|p| p == &parent) {
                parents.push(parent);
            }
        }
    }
    ssh_mkdir_p_many(remote, parents.iter().map(|s| s.as_str()))?;
    if !opts.json {
        eprintln!("bbx: push -r {} files → {}:{rpath}", files.len(), remote);
    }
    for (i, (local, rel)) in files.iter().enumerate() {
        let remote_file = join_remote(rpath, rel);
        if !opts.json {
            eprintln!("bbx: [{}/{}] {}", i + 1, files.len(), rel);
        } else {
            println!(
                r#"{{"event":"file","index":{},"total":{},"path":{:?}}}"#,
                i + 1,
                files.len(),
                rel
            );
        }
        let local_s = local.to_string_lossy();
        let mut o = opts;
        o.streams = streams_for_file(&local_s, opts.streams);
        if rev {
            cp_push_reverse(bin, remote, &remote_file, &local_s, o, port_range, fixed_key)?;
        } else {
            cp_push_forward(bin, remote, &remote_file, &local_s, o, port_range, fixed_key)?;
        }
    }
    if opts.json {
        println!(
            r#"{{"event":"tree_done","files":{},"direction":"push"}}"#,
            files.len()
        );
    } else {
        eprintln!("bbx: tree push done ({} files)", files.len());
    }
    Ok(())
}

pub(crate) fn cp_pull_tree(
    bin: &str,
    remote: &str,
    rpath: &str,
    local_dst: &str,
    opts: TransferOpts,
    rev: bool,
    port_range: Option<(u16, u16)>,
    fixed_key: Option<[u8; 32]>,
) -> Result<(), String> {
    let files = remote_list_files(remote, rpath)?;
    if files.is_empty() {
        return Err("no remote files found (need find -print0)".into());
    }
    let dest_root = Path::new(local_dst);
    std::fs::create_dir_all(dest_root).map_err(|e| e.to_string())?;
    if dest_path_has_symlink(dest_root, "")? {
        return Err(format!(
            "destination is a symlink (refused): {}",
            dest_root.display()
        ));
    }
    if !opts.json {
        eprintln!("bbx: pull -r {} files from {}:{rpath}", files.len(), remote);
    }
    for (i, rel) in files.iter().enumerate() {
        if !is_safe_rel(rel) {
            return Err(format!("unsafe remote path rejected: {rel:?}"));
        }
        if dest_path_has_symlink(dest_root, rel)? {
            return Err(format!(
                "refusing path with symlink under dest: {rel:?} (symlink escape)"
            ));
        }
        let remote_file = join_remote(rpath, rel);
        let local_file = dest_root.join(rel);
        if let Some(parent) = local_file.parent() {
            // Re-check parents after create: refuse if a parent became a symlink.
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            if dest_path_has_symlink(dest_root, rel)? {
                return Err(format!(
                    "refusing path with symlink under dest: {rel:?}"
                ));
            }
        }
        if !opts.json {
            eprintln!("bbx: [{}/{}] {}", i + 1, files.len(), rel);
        } else {
            println!(
                r#"{{"event":"file","index":{},"total":{},"path":{:?}}}"#,
                i + 1,
                files.len(),
                rel
            );
        }
        let local_s = local_file.to_string_lossy();
        // Pull: remote size unknown cheaply; use single stream for tree stability.
        let mut o = opts;
        o.streams = if opts.streams > 1 { 1 } else { opts.streams };
        if rev {
            cp_pull_reverse(bin, remote, &remote_file, &local_s, o, port_range, fixed_key)?;
        } else {
            cp_pull_forward(bin, remote, &remote_file, &local_s, o, port_range, fixed_key)?;
        }
    }
    if opts.json {
        println!(
            r#"{{"event":"tree_done","files":{},"direction":"pull"}}"#,
            files.len()
        );
    } else {
        eprintln!("bbx: tree pull done ({} files)", files.len());
    }
    Ok(())
}
