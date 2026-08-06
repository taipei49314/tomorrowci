//! Evidence directory layout and checksum helpers.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tomorrowci_core::{sha256_bytes, Result, RunManifest, TcError};

pub const RUNS_DIR: &str = ".tomorrowci/runs";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLayout {
    pub run_root: PathBuf,
}

impl EvidenceLayout {
    pub fn create(repo_root: &Path, run_id: &str) -> Result<Self> {
        let run_root = repo_root.join(RUNS_DIR).join(run_id);
        std::fs::create_dir_all(run_root.join("scenarios"))?;
        Ok(Self { run_root })
    }

    pub fn write_json<T: Serialize>(&self, name: &str, value: &T) -> Result<PathBuf> {
        let path = self.run_root.join(name);
        std::fs::write(&path, serde_json::to_string_pretty(value)?)?;
        Ok(path)
    }

    pub fn scenario_dir(&self, scenario_id: &str) -> PathBuf {
        self.run_root.join("scenarios").join(scenario_id)
    }

    pub fn ensure_scenario(&self, scenario_id: &str) -> Result<PathBuf> {
        let d = self.scenario_dir(scenario_id);
        std::fs::create_dir_all(&d)?;
        Ok(d)
    }
}

pub fn file_checksum(path: &Path) -> Result<String> {
    let data = std::fs::read(path)?;
    Ok(sha256_bytes(&data))
}

pub fn write_checksums(dir: &Path, files: &[(String, String)]) -> Result<()> {
    let mut lines = String::new();
    for (name, hash) in files {
        lines.push_str(&format!("{hash}  {name}\n"));
    }
    std::fs::write(dir.join("checksums.txt"), lines)?;
    Ok(())
}

pub fn write_run_manifest(layout: &EvidenceLayout, manifest: &RunManifest) -> Result<()> {
    layout.write_json("run.json", manifest)?;
    Ok(())
}

pub fn load_run_manifest(run_root: &Path) -> Result<RunManifest> {
    let raw = std::fs::read_to_string(run_root.join("run.json"))
        .map_err(|e| TcError::Other(format!("missing run.json for replay: {e}")))?;
    Ok(serde_json::from_str(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn creates_layout() {
        let d = tempdir().unwrap();
        let layout = EvidenceLayout::create(d.path(), "abc123").unwrap();
        assert!(layout.run_root.exists());
        layout.write_json("verdicts.json", &serde_json::json!([])).unwrap();
        assert!(layout.run_root.join("verdicts.json").exists());
    }
}
