//! Bounded, exact-commit materialization for remote GitHub scans.

use crate::orchestrate::{scan_local_into, ScanOptions, ScanOutcome};
use crate::synthetic_git::prepare_synthetic_git_index;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use tempfile::{Builder as TempBuilder, TempDir};
use tomorrowci_core::{Config, RemoteSourceRecord, Result, TcError};
use tomorrowci_evidence::{
    file_checksum, finalize_run_checksums, validate_existing_ancestors, verify_run_root,
    ChecksumCompatibility, WorkspaceManifest,
};

const CLONE_TIMEOUT_SECONDS: u64 = 120;
const MAX_FILES: u64 = 10_000;
const MAX_FILE_BYTES: u64 = 25 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 100 * 1024 * 1024;
const MAX_CLONE_DISK_BYTES: u64 = 256 * 1024 * 1024;
const MAX_GIT_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
struct RemoteFetchSpec {
    requested_url: String,
    fetch_url: String,
    checkout_origin_url: String,
    canonical_origin: String,
    allowed_protocol: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct TreeStats {
    file_count: u64,
    total_bytes: u64,
}

struct MaterializedRemote {
    _temp: TempDir,
    checkout: PathBuf,
    spec: RemoteFetchSpec,
    commit: String,
    tree: TreeStats,
}

impl MaterializedRemote {
    fn cleanup(self) -> Result<()> {
        self._temp.close().map_err(|error| {
            TcError::Blocked(format!(
                "remote scan completed but temporary checkout cleanup failed: {error}"
            ))
        })
    }
}

/// Materialize one immutable public GitHub commit, scan only its frozen
/// checkout, and retain evidence outside the temporary clone.
pub fn scan_remote_github(
    raw_url: &str,
    commit: &str,
    evidence_repo: &Path,
    explicit_config: Option<Config>,
) -> Result<ScanOutcome> {
    let spec = parse_github_url(raw_url)?;
    let materialized = materialize_exact_commit(spec, commit)?;
    let evidence_repo = validate_existing_ancestors(evidence_repo)?;
    let checkout = std::fs::canonicalize(&materialized.checkout)?;
    if evidence_repo.starts_with(&checkout)
        || checkout.starts_with(evidence_repo.join(".tomorrowci"))
    {
        return Err(TcError::InvalidState(
            "remote evidence root must be outside the temporary source checkout".into(),
        ));
    }

    let config = match explicit_config {
        Some(config) => config,
        None if checkout.join(".tomorrowci.yml").is_file() => {
            Config::load_file(&checkout.join(".tomorrowci.yml"))?
        }
        None => Config::default(),
    };

    let mut outcome = scan_local_into(
        &checkout,
        &evidence_repo,
        ScanOptions {
            config,
            allow_scripted: false,
        },
        true,
    )?;
    attach_remote_source_record(&materialized, &mut outcome)?;
    materialized.cleanup()?;
    Ok(outcome)
}

fn attach_remote_source_record(
    materialized: &MaterializedRemote,
    outcome: &mut ScanOutcome,
) -> Result<()> {
    let manifest = &outcome.manifest;
    if manifest.repository.source != materialized.spec.canonical_origin
        || manifest.repository.commit_sha.as_deref() != Some(materialized.commit.as_str())
        || manifest
            .identity
            .as_ref()
            .and_then(|identity| identity.dirty_tree)
            != Some(false)
        || manifest
            .identity
            .as_ref()
            .and_then(|identity| identity.source_commit.as_deref())
            != Some(materialized.commit.as_str())
    {
        return Err(TcError::Blocked(
            "remote origin, exact commit, or clean-tree identity changed during scan".into(),
        ));
    }
    ensure_exact_clean_checkout(
        &materialized.checkout,
        &materialized.spec,
        &materialized.commit,
    )?;

    let workspace_manifest_path = outcome.evidence_root.join("workspace-manifest.json");
    let workspace_manifest: WorkspaceManifest =
        serde_json::from_slice(&std::fs::read(&workspace_manifest_path)?)?;
    let snapshot_file_count = workspace_manifest.files.len() as u64;
    let snapshot_total_bytes = workspace_manifest
        .files
        .values()
        .try_fold(0_u64, |total, file| total.checked_add(file.size))
        .ok_or_else(|| TcError::InvalidState("workspace byte count overflowed".into()))?;
    if snapshot_file_count != materialized.tree.file_count
        || snapshot_total_bytes != materialized.tree.total_bytes
    {
        return Err(TcError::Blocked(
            "checked-out source tree does not exactly match the bounded Git tree inventory".into(),
        ));
    }

    let workspace_manifest_sha256 = file_checksum(&workspace_manifest_path)?;
    let synthetic_git_index = prepare_synthetic_git_index(
        &outcome.evidence_root.join("workspace"),
        &workspace_manifest,
        &workspace_manifest_sha256,
    )?;
    let record = RemoteSourceRecord {
        schema_version: 2,
        requested_url: materialized.spec.requested_url.clone(),
        canonical_origin: materialized.spec.canonical_origin.clone(),
        requested_commit: materialized.commit.clone(),
        resolved_commit: materialized.commit.clone(),
        clean_tree: true,
        moving_ref_allowed: false,
        redirects_allowed: false,
        credentials_allowed: false,
        submodules_allowed: false,
        lfs_allowed: false,
        clone_timeout_seconds: CLONE_TIMEOUT_SECONDS,
        max_files: MAX_FILES,
        max_file_bytes: MAX_FILE_BYTES,
        max_total_bytes: MAX_TOTAL_BYTES,
        max_clone_disk_bytes: MAX_CLONE_DISK_BYTES,
        snapshot_file_count,
        snapshot_total_bytes,
        workspace_manifest_sha256,
        synthetic_git_index: Some(synthetic_git_index.record),
    };
    std::fs::write(
        outcome.evidence_root.join("remote-source.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;
    finalize_run_checksums(&outcome.evidence_root)?;
    let verification = verify_run_root(&outcome.evidence_root)?;
    if !verification.ok || verification.checksum_compatibility != ChecksumCompatibility::CurrentV2 {
        return Err(TcError::InvalidState(format!(
            "remote current-v2 evidence verification failed: {}",
            verification.errors.join("; ")
        )));
    }
    Ok(())
}

fn parse_github_url(raw: &str) -> Result<RemoteFetchSpec> {
    if raw.len() > 256 || raw.trim() != raw || raw.contains(['\r', '\n', '\0', '?', '#', '%']) {
        return Err(TcError::InvalidState(
            "remote URL must be one canonical HTTPS GitHub repository URL".into(),
        ));
    }
    let path = raw.strip_prefix("https://github.com/").ok_or_else(|| {
        TcError::InvalidState("remote URL must use https://github.com/<owner>/<repository>".into())
    })?;
    if path.contains('@') || path.contains(':') || path.ends_with('/') {
        return Err(TcError::InvalidState(
            "remote URL credentials, ports, and trailing slashes are forbidden".into(),
        ));
    }
    let mut parts = path.split('/');
    let owner = parts.next().unwrap_or_default();
    let raw_repo = parts.next().unwrap_or_default();
    if parts.next().is_some() {
        return Err(TcError::InvalidState(
            "remote URL must identify exactly one owner and repository".into(),
        ));
    }
    let repo = raw_repo.strip_suffix(".git").unwrap_or(raw_repo);
    if !valid_github_component(owner) || !valid_github_component(repo) || repo.ends_with(".git") {
        return Err(TcError::InvalidState(
            "remote GitHub owner or repository name is not canonical".into(),
        ));
    }
    let requested_url = format!("https://github.com/{owner}/{repo}");
    Ok(RemoteFetchSpec {
        fetch_url: format!("{requested_url}.git"),
        checkout_origin_url: format!("{requested_url}.git"),
        canonical_origin: format!("origin:{requested_url}"),
        requested_url,
        allowed_protocol: "https",
    })
}

fn valid_github_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_exact_commit(commit: &str) -> Result<()> {
    if commit.len() != 40
        || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        || commit.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(TcError::InvalidState(
            "remote --commit must be exactly 40 lowercase hexadecimal characters; refs and branch names are forbidden"
                .into(),
        ));
    }
    Ok(())
}

fn materialize_exact_commit(spec: RemoteFetchSpec, commit: &str) -> Result<MaterializedRemote> {
    validate_exact_commit(commit)?;
    let temp = TempBuilder::new()
        .prefix("tomorrowci-remote-")
        .tempdir()
        .map_err(|error| TcError::Blocked(format!("cannot create remote staging root: {error}")))?;
    let checkout = temp.path().join("source");
    std::fs::create_dir(&checkout)?;
    let empty_config = temp.path().join("empty-gitconfig");
    std::fs::write(&empty_config, [])?;
    let hooks = temp.path().join("empty-hooks");
    std::fs::create_dir(&hooks)?;
    let git = GitRunner::new(&checkout, empty_config, hooks);

    git.checked(&["init", "--quiet", "."], "initialize isolated checkout")?;
    for (key, value) in [
        ("core.autocrlf", "false"),
        ("core.symlinks", "false"),
        ("core.filemode", "false"),
        ("advice.detachedHead", "false"),
    ] {
        git.checked(&["config", "--local", key, value], "set safe Git config")?;
    }
    git.checked(
        &["config", "--local", "core.hooksPath", &git.hooks_string()],
        "disable repository hooks",
    )?;
    git.checked(
        &["remote", "add", "origin", &spec.fetch_url],
        "set bounded remote origin",
    )?;

    let protocol_allow = format!("protocol.{}.allow=always", spec.allowed_protocol);
    git.checked(
        &[
            "-c",
            "protocol.allow=never",
            "-c",
            &protocol_allow,
            "-c",
            "http.followRedirects=false",
            "-c",
            "credential.helper=",
            "-c",
            "core.askPass=",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "filter.lfs.process=",
            "-c",
            "filter.lfs.required=false",
            "fetch",
            "--quiet",
            "--no-tags",
            "--depth=1",
            "origin",
            commit,
        ],
        "fetch exact remote commit",
    )?;
    enforce_clone_disk_limit(&checkout)?;

    let resolved = git.text(
        &["rev-parse", "--verify", "FETCH_HEAD^{commit}"],
        "resolve fetched commit",
    )?;
    if resolved != commit {
        return Err(TcError::Blocked(format!(
            "remote commit identity mismatch: requested {commit}, fetched {resolved}"
        )));
    }
    let tree_output = git.checked(
        &["ls-tree", "-rlz", "--full-tree", commit],
        "inventory exact remote tree",
    )?;
    let tree = validate_tree_inventory(&tree_output)?;

    git.checked(
        &[
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "filter.lfs.process=",
            "-c",
            "filter.lfs.required=false",
            "checkout",
            "--quiet",
            "--detach",
            "--force",
            commit,
        ],
        "checkout exact remote commit",
    )?;
    reject_lfs_attributes(&checkout)?;
    enforce_clone_disk_limit(&checkout)?;
    git.checked(
        &["remote", "set-url", "origin", &spec.checkout_origin_url],
        "freeze canonical evidence origin",
    )?;
    ensure_exact_clean_checkout(&checkout, &spec, commit)?;

    Ok(MaterializedRemote {
        _temp: temp,
        checkout,
        spec,
        commit: commit.to_string(),
        tree,
    })
}

fn ensure_exact_clean_checkout(
    checkout: &Path,
    spec: &RemoteFetchSpec,
    commit: &str,
) -> Result<()> {
    let git = GitRunner::for_existing(checkout)?;
    let head = git.text(
        &["rev-parse", "--verify", "HEAD^{commit}"],
        "verify materialized HEAD",
    )?;
    if head != commit {
        return Err(TcError::Blocked(format!(
            "materialized HEAD moved: expected {commit}, found {head}"
        )));
    }
    let branch = git.text(
        &["rev-parse", "--abbrev-ref", "HEAD"],
        "verify detached HEAD",
    )?;
    if branch != "HEAD" {
        return Err(TcError::Blocked(
            "remote materialization unexpectedly follows a moving branch".into(),
        ));
    }
    let origin = git.text(&["remote", "get-url", "origin"], "verify remote origin")?;
    if origin != spec.checkout_origin_url {
        return Err(TcError::Blocked(
            "remote origin changed after exact-commit materialization".into(),
        ));
    }
    let status = git.checked(
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        "verify clean remote source",
    )?;
    if !status.is_empty() {
        return Err(TcError::Blocked(
            "remote source became dirty during materialization or scan".into(),
        ));
    }
    Ok(())
}

fn validate_tree_inventory(raw: &[u8]) -> Result<TreeStats> {
    let mut file_count = 0_u64;
    let mut total_bytes = 0_u64;
    let mut portable_paths = BTreeSet::new();
    for entry in raw
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let tab = entry
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| {
                TcError::Blocked("remote Git tree entry has no canonical path separator".into())
            })?;
        let header = std::str::from_utf8(&entry[..tab])
            .map_err(|_| TcError::Blocked("remote Git tree metadata is not UTF-8".into()))?;
        let path = std::str::from_utf8(&entry[tab + 1..])
            .map_err(|_| TcError::Blocked("remote Git path is not UTF-8".into()))?;
        let fields: Vec<_> = header.split_whitespace().collect();
        if fields.len() != 4 || !matches!(fields[0], "100644" | "100755") || fields[1] != "blob" {
            return Err(TcError::Blocked(format!(
                "remote tree contains a forbidden file type at {path:?}"
            )));
        }
        validate_tree_path(path)?;
        if !portable_paths.insert(path.to_ascii_lowercase()) {
            return Err(TcError::Blocked(format!(
                "remote tree contains a case-colliding path: {path:?}"
            )));
        }
        let size = fields[3].parse::<u64>().map_err(|_| {
            TcError::Blocked(format!("remote tree has no bounded blob size at {path:?}"))
        })?;
        if size > MAX_FILE_BYTES {
            return Err(TcError::Blocked(format!(
                "remote file exceeds {} bytes: {path}",
                MAX_FILE_BYTES
            )));
        }
        file_count = file_count
            .checked_add(1)
            .ok_or_else(|| TcError::Blocked("remote file count overflowed".into()))?;
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or_else(|| TcError::Blocked("remote tree byte count overflowed".into()))?;
        if file_count > MAX_FILES || total_bytes > MAX_TOTAL_BYTES {
            return Err(TcError::Blocked(
                "remote tree exceeds the bounded file-count or byte budget".into(),
            ));
        }
    }
    Ok(TreeStats {
        file_count,
        total_bytes,
    })
}

fn validate_tree_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return Err(TcError::Blocked(format!(
            "remote tree contains an unsafe path: {path:?}"
        )));
    }
    const IGNORED_COMPONENTS: &[&str] = &[
        ".git",
        ".tomorrowci",
        "target",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
    ];
    for component in path.split('/') {
        let lowered = component.to_ascii_lowercase();
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains(':')
            || component.trim_end_matches([' ', '.']) != component
            || IGNORED_COMPONENTS.contains(&lowered.as_str())
            || windows_reserved_name(&lowered)
        {
            return Err(TcError::Blocked(format!(
                "remote tree contains an unsafe path component: {path:?}"
            )));
        }
    }
    let basename = path
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(basename.as_str(), ".gitmodules" | ".lfsconfig") {
        return Err(TcError::Blocked(format!(
            "remote submodule/LFS metadata is forbidden: {path}"
        )));
    }
    Ok(())
}

fn windows_reserved_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    matches!(stem, "con" | "prn" | "aux" | "nul")
        || stem
            .strip_prefix("com")
            .or_else(|| stem.strip_prefix("lpt"))
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

fn reject_lfs_attributes(checkout: &Path) -> Result<()> {
    let mut pending = vec![checkout.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(TcError::Blocked(format!(
                    "remote checkout contains a forbidden symlink: {}",
                    path.display()
                )));
            }
            if metadata.is_dir() {
                if entry.file_name() != ".git" {
                    pending.push(path);
                }
                continue;
            }
            if entry.file_name() == ".gitattributes" {
                let text = std::fs::read_to_string(&path).map_err(|_| {
                    TcError::Blocked(format!(
                        "remote .gitattributes is not bounded UTF-8 text: {}",
                        path.display()
                    ))
                })?;
                if text
                    .split_whitespace()
                    .any(|token| token.to_ascii_lowercase().starts_with("filter=lfs"))
                {
                    return Err(TcError::Blocked(format!(
                        "Git LFS materialization is forbidden: {}",
                        path.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

fn enforce_clone_disk_limit(root: &Path) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut total = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(TcError::Blocked(format!(
                    "remote staging contains a forbidden filesystem alias: {}",
                    path.display()
                )));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                total = total
                    .checked_add(metadata.len())
                    .ok_or_else(|| TcError::Blocked("remote clone size overflowed".into()))?;
                if total > MAX_CLONE_DISK_BYTES {
                    return Err(TcError::Blocked(format!(
                        "remote clone exceeds the {} byte disk budget",
                        MAX_CLONE_DISK_BYTES
                    )));
                }
            } else {
                return Err(TcError::Blocked(format!(
                    "remote staging contains a forbidden file type: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

fn staging_exceeds_disk_budget(root: &Path) -> std::io::Result<bool> {
    let mut pending = vec![root.to_path_buf()];
    let mut total = 0_u64;
    while let Some(directory) = pending.pop() {
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let metadata = match std::fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if metadata.file_type().is_symlink() {
                return Ok(true);
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                total = match total.checked_add(metadata.len()) {
                    Some(total) => total,
                    None => return Ok(true),
                };
                if total > MAX_CLONE_DISK_BYTES {
                    return Ok(true);
                }
            } else {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

struct GitRunner {
    cwd: PathBuf,
    empty_config: PathBuf,
    hooks: PathBuf,
}

struct GitOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
}

impl GitRunner {
    fn new(cwd: &Path, empty_config: PathBuf, hooks: PathBuf) -> Self {
        Self {
            cwd: cwd.to_path_buf(),
            empty_config,
            hooks,
        }
    }

    fn for_existing(cwd: &Path) -> Result<Self> {
        let git_dir = cwd.join(".git");
        Ok(Self {
            cwd: cwd.to_path_buf(),
            empty_config: git_dir.join("tomorrowci-empty-global-config"),
            hooks: git_dir.join("tomorrowci-empty-hooks"),
        })
    }

    fn hooks_string(&self) -> String {
        self.hooks.to_string_lossy().into_owned()
    }

    fn text(&self, args: &[&str], operation: &str) -> Result<String> {
        let raw = self.checked(args, operation)?;
        let text = std::str::from_utf8(&raw)
            .map_err(|_| TcError::Blocked(format!("{operation} returned non-UTF-8 output")))?;
        Ok(text.trim().to_string())
    }

    fn checked(&self, args: &[&str], operation: &str) -> Result<Vec<u8>> {
        let output = self.run(args, operation)?;
        if output.truncated {
            return Err(TcError::Blocked(format!(
                "{operation} exceeded the bounded diagnostic output budget"
            )));
        }
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TcError::Blocked(format!(
                "{operation} failed with {}: {}",
                output.status,
                stderr.trim()
            )));
        }
        Ok(output.stdout)
    }

    fn run(&self, args: &[&str], operation: &str) -> Result<GitOutput> {
        let mut command = Command::new("git");
        command
            .args(args)
            .current_dir(&self.cwd)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &self.empty_config)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GCM_INTERACTIVE", "Never")
            .env("GIT_LFS_SKIP_SMUDGE", "1")
            .env("GIT_ASKPASS", "")
            .env_remove("SSH_ASKPASS")
            .env_remove("GIT_CONFIG_COUNT")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| {
            TcError::Blocked(format!("cannot start Git for {operation}: {error}"))
        })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| TcError::Blocked("cannot capture Git stdout".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| TcError::Blocked("cannot capture Git stderr".into()))?;
        let stdout_reader = std::thread::spawn(move || read_bounded(stdout));
        let stderr_reader = std::thread::spawn(move || read_bounded(stderr));

        let deadline = Instant::now() + Duration::from_secs(CLONE_TIMEOUT_SECONDS);
        let mut next_disk_check = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(TcError::Blocked(format!(
                        "{operation} exceeded the {CLONE_TIMEOUT_SECONDS} second timeout"
                    )));
                }
                Ok(None) => {
                    if Instant::now() >= next_disk_check {
                        match staging_exceeds_disk_budget(&self.cwd) {
                            Ok(false) => {}
                            Ok(true) => {
                                let _ = child.kill();
                                let _ = child.wait();
                                let _ = stdout_reader.join();
                                let _ = stderr_reader.join();
                                return Err(TcError::Blocked(format!(
                                    "{operation} exceeded the {MAX_CLONE_DISK_BYTES} byte clone disk budget"
                                )));
                            }
                            Err(error) => {
                                let _ = child.kill();
                                let _ = child.wait();
                                let _ = stdout_reader.join();
                                let _ = stderr_reader.join();
                                return Err(TcError::Blocked(format!(
                                    "cannot enforce clone disk budget during {operation}: {error}"
                                )));
                            }
                        }
                        next_disk_check = Instant::now() + Duration::from_millis(250);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(TcError::Blocked(format!(
                        "cannot monitor Git process for {operation}: {error}"
                    )));
                }
            }
        };
        let (stdout, stdout_truncated) = stdout_reader
            .join()
            .map_err(|_| TcError::Blocked("Git stdout reader failed".into()))??;
        let (stderr, stderr_truncated) = stderr_reader
            .join()
            .map_err(|_| TcError::Blocked("Git stderr reader failed".into()))??;
        Ok(GitOutput {
            status,
            stdout,
            stderr,
            truncated: stdout_truncated || stderr_truncated,
        })
    }
}

fn read_bounded(mut reader: impl Read) -> std::io::Result<(Vec<u8>, bool)> {
    let mut captured = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_GIT_OUTPUT_BYTES.saturating_sub(captured.len());
        let keep = remaining.min(read);
        captured.extend_from_slice(&buffer[..keep]);
        truncated |= keep < read;
    }
    Ok((captured, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{ExecutionContext, ScenarioExecutor};
    use crate::orchestrate::{replay_scenario_with_executor, scan_local_with_executor_into};
    use tomorrowci_core::{RawExecutionResult, SYNTHETIC_GIT_ENV, SYNTHETIC_GIT_INDEX_KIND};

    struct ExactTestExecutor;

    impl ScenarioExecutor for ExactTestExecutor {
        fn name(&self) -> &str {
            "test-container"
        }

        fn engine_label(&self) -> String {
            "docker".into()
        }

        fn engine_version(&self) -> Option<String> {
            Some("test-docker-1".into())
        }

        fn ensure_image(&self, _image: &str) -> Result<String> {
            Ok(format!("sha256:{}", "a".repeat(64)))
        }

        fn execute(&self, context: &ExecutionContext<'_>) -> Result<RawExecutionResult> {
            let listed = Command::new("git")
                .args(["ls-files", "-z"])
                .current_dir(context.workspace)
                .output()
                .unwrap();
            assert!(
                listed.status.success(),
                "{}",
                String::from_utf8_lossy(&listed.stderr)
            );
            assert_eq!(
                listed.stdout,
                b"app.py\0requirements.txt\0tests/test_app.py\0".to_vec()
            );
            for (key, value) in SYNTHETIC_GIT_ENV {
                assert_eq!(
                    context.environment.env.get(*key).map(String::as_str),
                    Some(*value)
                );
            }
            assert!(context
                .environment
                .env
                .keys()
                .filter(|key| key.starts_with("GIT_"))
                .all(|key| SYNTHETIC_GIT_ENV.iter().any(|(allowed, _)| key == allowed)));
            let fetch = context
                .commands
                .iter()
                .all(|command| command.phase == "fetch");
            let failed = !fetch && !context.scenario.is_baseline;
            Ok(RawExecutionResult {
                workspace_preparation: None,
                exit_code: Some(if failed { 1 } else { 0 }),
                signal: None,
                duration_ms: 1,
                timed_out: false,
                stdout: if failed { String::new() } else { "ok\n".into() },
                stderr: if failed {
                    "ImportError: cannot import name 'MutableMapping' from 'collections'\n".into()
                } else {
                    String::new()
                },
                network_used: context.network != "none",
            })
        }
    }

    fn git(cwd: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn local_spec(bare: &Path) -> RemoteFetchSpec {
        let fetch_url = format!("file:///{}", bare.display().to_string().replace('\\', "/"));
        RemoteFetchSpec {
            requested_url: "https://github.com/example/remote-fixture".into(),
            fetch_url,
            checkout_origin_url: "https://github.com/example/remote-fixture.git".into(),
            canonical_origin: "origin:https://github.com/example/remote-fixture".into(),
            allowed_protocol: "file",
        }
    }

    #[test]
    fn github_url_and_commit_grammar_fail_closed() {
        for bad in [
            "http://github.com/o/r",
            "https://user@github.com/o/r",
            "https://github.com:443/o/r",
            "https://github.com/o/r/tree/main",
            "https://github.com/o/r?ref=main",
            "https://github.com/o/%72",
            "https://evil.example/o/r",
        ] {
            assert!(parse_github_url(bad).is_err(), "accepted {bad}");
        }
        assert!(parse_github_url("https://github.com/o/r").is_ok());
        assert!(parse_github_url("https://github.com/o/r.git").is_ok());
        for bad in ["main", "a", &"A".repeat(40), &"a".repeat(39)] {
            assert!(validate_exact_commit(bad).is_err(), "accepted {bad}");
        }
        assert!(validate_exact_commit(&"a".repeat(40)).is_ok());
    }

    #[test]
    fn tree_inventory_rejects_aliases_submodules_and_ignored_paths() {
        for raw in [
            b"120000 blob 0123456789012345678901234567890123456789 4\tlink\0".as_slice(),
            b"160000 commit 0123456789012345678901234567890123456789 -\tmodule\0".as_slice(),
            b"100644 blob 0123456789012345678901234567890123456789 4\t.gitmodules\0".as_slice(),
            b"100644 blob 0123456789012345678901234567890123456789 4\ttarget/out\0".as_slice(),
            b"100644 blob 0123456789012345678901234567890123456789 4\t../escape\0".as_slice(),
        ] {
            assert!(validate_tree_inventory(raw).is_err());
        }
        let case_collision = concat!(
            "100644 blob 0123456789012345678901234567890123456789 1\tReadme.md\0",
            "100644 blob 1123456789012345678901234567890123456789 1\tREADME.md\0"
        );
        assert!(validate_tree_inventory(case_collision.as_bytes()).is_err());
        let oversized = format!(
            "100644 blob 0123456789012345678901234567890123456789 {}\tlarge.bin\0",
            MAX_FILE_BYTES + 1
        );
        assert!(validate_tree_inventory(oversized.as_bytes()).is_err());
    }

    #[test]
    fn exact_commit_survives_branch_movement_and_temp_clone_cleanup() {
        let fixture = tempfile::tempdir().unwrap();
        let source = fixture.path().join("source");
        let bare = fixture.path().join("remote.git");
        let evidence = fixture.path().join("evidence");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&evidence).unwrap();
        git(&source, &["init", "--quiet"]);
        git(&source, &["config", "user.name", "TomorrowCI Test"]);
        git(&source, &["config", "user.email", "test@example.invalid"]);
        std::fs::write(source.join("requirements.txt"), "pytest==7.4.4\n").unwrap();
        std::fs::write(source.join("app.py"), "VALUE = 'first'\n").unwrap();
        std::fs::create_dir(source.join("tests")).unwrap();
        std::fs::write(
            source.join("tests/test_app.py"),
            "import app\ndef test_value(): assert app.VALUE == 'first'\n",
        )
        .unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "--quiet", "-m", "first"]);
        let first = git(&source, &["rev-parse", "HEAD"]);
        git(fixture.path(), &["init", "--quiet", "--bare", "remote.git"]);
        git(
            &source,
            &["remote", "add", "origin", bare.to_str().unwrap()],
        );
        git(&source, &["push", "--quiet", "origin", "HEAD:main"]);

        let materialized = materialize_exact_commit(local_spec(&bare), &first).unwrap();
        assert_eq!(
            std::fs::read_to_string(materialized.checkout.join("app.py")).unwrap(),
            "VALUE = 'first'\n"
        );

        std::fs::write(source.join("app.py"), "VALUE = 'second'\n").unwrap();
        git(&source, &["add", "app.py"]);
        git(&source, &["commit", "--quiet", "-m", "second"]);
        git(&source, &["push", "--quiet", "origin", "HEAD:main"]);

        let mut config = Config::default();
        config.baseline.runtime = "3.9".into();
        config.candidates.runtime.max_versions = 1;
        config.candidates.dependencies.latest_allowed = false;
        config.execution.reruns_on_failure = 2;
        config.execution.max_scenarios = 2;
        let mut outcome = scan_local_with_executor_into(
            &materialized.checkout,
            &evidence,
            config,
            &ExactTestExecutor,
        )
        .unwrap();
        attach_remote_source_record(&materialized, &mut outcome).unwrap();
        let run_id = outcome.manifest.run_id.clone();
        let candidate = outcome
            .manifest
            .frontier
            .first_failing_scenario
            .clone()
            .unwrap();
        let staging = materialized.checkout.clone();
        materialized.cleanup().unwrap();
        assert!(!staging.exists(), "temporary clone was not cleaned up");

        let workspace = outcome.evidence_root.join("workspace");
        assert!(!workspace.join(".git").exists());
        assert_eq!(
            std::fs::read_to_string(workspace.join("app.py")).unwrap(),
            "VALUE = 'first'\n"
        );
        let before = verify_run_root(&outcome.evidence_root).unwrap();
        assert!(before.ok, "{}", before.errors.join("; "));
        assert_eq!(
            before.checksum_compatibility,
            ChecksumCompatibility::CurrentV2
        );
        let replay =
            replay_scenario_with_executor(&evidence, &run_id, &candidate, &ExactTestExecutor)
                .unwrap();
        assert!(replay.contains("signature_match=true"));
        assert!(replay.contains("exit_match=true"));
        let after = verify_run_root(&outcome.evidence_root).unwrap();
        assert!(after.ok, "{}", after.errors.join("; "));
        assert_eq!(
            after.checksum_compatibility,
            ChecksumCompatibility::CurrentV2
        );

        let run_path = outcome.evidence_root.join("run.json");
        let original_run = std::fs::read(&run_path).unwrap();
        let mut forged_run: serde_json::Value = serde_json::from_slice(&original_run).unwrap();
        forged_run["results"][0]["environment"]["env"]["GIT_DIR"] =
            serde_json::json!("/tmp/forged");
        std::fs::write(&run_path, serde_json::to_vec_pretty(&forged_run).unwrap()).unwrap();
        finalize_run_checksums(&outcome.evidence_root).unwrap();
        let rejected_environment = verify_run_root(&outcome.evidence_root).unwrap();
        assert!(!rejected_environment.ok);
        assert!(rejected_environment
            .errors
            .iter()
            .any(|error| error.contains("does not bind the synthetic Git environment")));
        std::fs::write(&run_path, &original_run).unwrap();
        finalize_run_checksums(&outcome.evidence_root).unwrap();

        let remote_path = outcome.evidence_root.join("remote-source.json");
        let original_remote = std::fs::read(&remote_path).unwrap();
        let original_value: serde_json::Value = serde_json::from_slice(&original_remote).unwrap();
        assert_eq!(original_value["schema_version"], 2);
        assert_eq!(
            original_value["synthetic_git_index"]["kind"],
            SYNTHETIC_GIT_INDEX_KIND
        );
        let mut legacy_v1 = original_value.clone();
        legacy_v1["schema_version"] = serde_json::json!(1);
        legacy_v1
            .as_object_mut()
            .unwrap()
            .remove("synthetic_git_index");
        std::fs::write(&remote_path, serde_json::to_vec_pretty(&legacy_v1).unwrap()).unwrap();
        finalize_run_checksums(&outcome.evidence_root).unwrap();
        let legacy_verify = verify_run_root(&outcome.evidence_root).unwrap();
        assert!(
            legacy_verify.ok,
            "legacy v1 read compatibility: {}",
            legacy_verify.errors.join("; ")
        );
        let legacy_replay =
            replay_scenario_with_executor(&evidence, &run_id, &candidate, &ExactTestExecutor)
                .unwrap_err();
        assert!(legacy_replay.to_string().contains("verify-only"));

        std::fs::write(&remote_path, &original_remote).unwrap();
        finalize_run_checksums(&outcome.evidence_root).unwrap();
        let mut forged_index = original_value.clone();
        forged_index["synthetic_git_index"]["index_sha256"] =
            serde_json::json!(format!("sha256:{}", "f".repeat(64)));
        std::fs::write(
            &remote_path,
            serde_json::to_vec_pretty(&forged_index).unwrap(),
        )
        .unwrap();
        finalize_run_checksums(&outcome.evidence_root).unwrap();
        let rejected_index = verify_run_root(&outcome.evidence_root).unwrap();
        assert!(!rejected_index.ok);
        assert!(rejected_index
            .errors
            .iter()
            .any(|error| error.contains("synthetic Git index")));

        std::fs::write(&remote_path, &original_remote).unwrap();
        finalize_run_checksums(&outcome.evidence_root).unwrap();
        let mut forged: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&remote_path).unwrap()).unwrap();
        forged["resolved_commit"] = serde_json::json!("b".repeat(40));
        std::fs::write(&remote_path, serde_json::to_vec_pretty(&forged).unwrap()).unwrap();
        finalize_run_checksums(&outcome.evidence_root).unwrap();
        let rejected = verify_run_root(&outcome.evidence_root).unwrap();
        assert!(!rejected.ok);
        assert!(rejected
            .errors
            .iter()
            .any(|error| error.contains("exact commit")));
    }
}
