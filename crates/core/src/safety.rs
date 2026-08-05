//! Path and symlink safety for untrusted workspaces.

use crate::error::{CoreError, Result};
use std::path::{Component, Path, PathBuf};

/// Reject paths that escape a root via `..` or absolute segments.
pub fn ensure_within_root(root: &Path, candidate: &Path) -> Result<PathBuf> {
    let root = root
        .canonicalize()
        .map_err(|e| CoreError::Validation(format!("root canonicalize: {e}")))?;
    // If candidate doesn't exist yet, canonicalize parent + join
    let resolved = if candidate.exists() {
        candidate
            .canonicalize()
            .map_err(|e| CoreError::Validation(format!("path canonicalize: {e}")))?
    } else {
        let parent = candidate.parent().unwrap_or(Path::new("."));
        let file = candidate
            .file_name()
            .ok_or_else(|| CoreError::Validation("candidate path has no file name".into()))?;
        let parent = if parent.as_os_str().is_empty() {
            root.clone()
        } else if parent.exists() {
            parent
                .canonicalize()
                .map_err(|e| CoreError::Validation(format!("parent canonicalize: {e}")))?
        } else {
            // Walk components carefully
            normalize_join(&root, candidate)?
        };
        if parent.exists() {
            parent.join(file)
        } else {
            normalize_join(&root, candidate)?
        }
    };

    if !resolved.starts_with(&root) {
        return Err(CoreError::Validation(format!(
            "path escape rejected: {} is outside {}",
            resolved.display(),
            root.display()
        )));
    }
    Ok(resolved)
}

fn normalize_join(root: &Path, candidate: &Path) -> Result<PathBuf> {
    let mut out = root.to_path_buf();
    for c in candidate.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => {
                return Err(CoreError::Validation(
                    "absolute paths are not allowed inside workspace mounts".into(),
                ));
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() || !out.starts_with(root) {
                    return Err(CoreError::Validation("path escape via .. rejected".into()));
                }
            }
            Component::Normal(s) => out.push(s),
        }
    }
    Ok(out)
}

/// Check a directory tree for symlink escapes outside root.
pub fn reject_symlink_escapes(root: &Path) -> Result<()> {
    let root = root
        .canonicalize()
        .map_err(|e| CoreError::Validation(format!("root: {e}")))?;
    walk_check(&root, &root)?;
    Ok(())
}

fn walk_check(root: &Path, dir: &Path) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| CoreError::Validation(format!("read_dir {}: {e}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| CoreError::Validation(e.to_string()))?;
        let path = entry.path();
        let meta =
            std::fs::symlink_metadata(&path).map_err(|e| CoreError::Validation(e.to_string()))?;
        if meta.file_type().is_symlink() {
            let target =
                std::fs::read_link(&path).map_err(|e| CoreError::Validation(e.to_string()))?;
            let resolved = if target.is_absolute() {
                target
            } else {
                path.parent().unwrap_or(dir).join(target)
            };
            let resolved = if resolved.exists() {
                resolved.canonicalize().unwrap_or(resolved)
            } else {
                resolved
            };
            if !resolved.starts_with(root) {
                return Err(CoreError::Validation(format!(
                    "symlink escape rejected: {} -> {}",
                    path.display(),
                    resolved.display()
                )));
            }
        } else if meta.is_dir() {
            walk_check(root, &path)?;
        }
    }
    Ok(())
}

/// Escape untrusted text for HTML embedding.
pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn rejects_dotdot_escape() {
        let dir = tempdir().unwrap();
        let err = ensure_within_root(dir.path(), Path::new("../etc/passwd"));
        assert!(err.is_err());
    }

    #[test]
    fn accepts_nested_path() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("a").join("b.txt");
        fs::create_dir_all(nested.parent().unwrap()).unwrap();
        fs::write(&nested, "x").unwrap();
        let ok = ensure_within_root(dir.path(), &nested).unwrap();
        assert!(ok.ends_with("b.txt"));
    }

    #[test]
    fn html_escape() {
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
    }

    #[test]
    #[cfg(unix)]
    fn symlink_escape_detected() {
        let dir = tempdir().unwrap();
        let link = dir.path().join("evil");
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        assert!(reject_symlink_escapes(dir.path()).is_err());
    }
}
