use crate::domain::ContentHash;
use crate::error::{Result as TcResult, TcError};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub fn sha256_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("sha256:{}", hex::encode(h.finalize()))
}

pub fn sha256_str(s: &str) -> String {
    sha256_bytes(s.as_bytes())
}

/// Hash a regular artifact without loading the entire wheel into memory.
/// Callers must additionally reject aliases in the workspace-relative ancestors.
pub fn sha256_file_v1(path: &Path) -> TcResult<ContentHash> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata_is_alias(&metadata) || !metadata.is_file() {
        return Err(TcError::Config(format!(
            "dependency source must be a plain file: {}",
            path.display()
        )));
    }
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    ContentHash::sha256(hex::encode(hasher.finalize())).map_err(TcError::InvalidState)
}

pub fn canonical_json_hash<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let v = serde_json::to_value(value)?;
    let s = serde_json::to_string(&canonicalize(&v))?;
    Ok(sha256_str(&s))
}

/// Content identity for a vendored dependency directory.
///
/// The preimage is each UTF-8 forward-slash relative path, NUL, the bare
/// lowercase SHA-256 of that file, and LF, ordered lexicographically by path.
/// Aliases and non-regular entries fail closed.
pub fn sha256_tree_v1(root: &Path) -> TcResult<ContentHash> {
    let metadata = std::fs::symlink_metadata(root)?;
    if metadata_is_alias(&metadata) || !metadata.is_dir() {
        return Err(TcError::Config(format!(
            "dependency source must be a plain directory: {}",
            root.display()
        )));
    }
    let mut files = Vec::new();
    collect_tree_files(root, root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let mut canonical = Vec::new();
    for (relative, path) in files {
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata_is_alias(&metadata) || !metadata.is_file() {
            return Err(TcError::Config(format!(
                "dependency source changed while hashing: {}",
                path.display()
            )));
        }
        let bytes = std::fs::read(path)?;
        let digest = sha256_bytes(&bytes);
        canonical.extend_from_slice(relative.as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(digest.trim_start_matches("sha256:").as_bytes());
        canonical.push(b'\n');
    }
    Ok(ContentHash::of_bytes(&canonical))
}

fn collect_tree_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> TcResult<()> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata_is_alias(&metadata) {
            return Err(TcError::Config(format!(
                "dependency source contains a symlink/reparse entry: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_tree_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path.strip_prefix(root).map_err(|_| {
                TcError::InvalidState("dependency tree escaped its source root".into())
            })?;
            let mut components = Vec::new();
            for component in relative.components() {
                let std::path::Component::Normal(component) = component else {
                    return Err(TcError::Config(format!(
                        "dependency source contains a noncanonical path: {}",
                        relative.display()
                    )));
                };
                components.push(component.to_str().ok_or_else(|| {
                    TcError::Config("dependency source paths must be valid UTF-8".into())
                })?);
            }
            files.push((components.join("/"), path));
        } else {
            return Err(TcError::Config(format!(
                "dependency source contains a non-regular entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn metadata_is_alias(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

fn canonicalize(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonicalize(&map[&k]));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(canonicalize).collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn key_order_stable() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(
            canonical_json_hash(&a).unwrap(),
            canonical_json_hash(&b).unwrap()
        );
    }

    #[test]
    fn tree_hash_is_ordered_and_content_sensitive() {
        let root = tempdir().unwrap();
        std::fs::create_dir(root.path().join("nested")).unwrap();
        std::fs::write(root.path().join("z.txt"), "z\n").unwrap();
        std::fs::write(root.path().join("nested/a.txt"), "a\n").unwrap();
        let first = sha256_tree_v1(root.path()).unwrap();
        assert_eq!(first, sha256_tree_v1(root.path()).unwrap());
        std::fs::write(root.path().join("nested/a.txt"), "changed\n").unwrap();
        assert_ne!(first, sha256_tree_v1(root.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn tree_hash_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        std::fs::write(root.path().join("target"), "bytes").unwrap();
        symlink("target", root.path().join("alias")).unwrap();
        assert!(sha256_tree_v1(root.path()).is_err());
    }
}
