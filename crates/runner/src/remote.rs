//! Fail-closed, bounded acquisition of public GitHub repositories.
//!
//! This module deliberately shells out to the installed `git`, but isolates it
//! from ambient Git configuration and credentials. A clone only becomes usable
//! after its canonical origin, exact commit object, and clean worktree have all
//! been verified.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;
use walkdir::WalkDir;

use crate::{Result, RunnerError};

/// Remote acquisition has one wall-clock budget, including provenance checks.
pub(crate) const REMOTE_CLONE_TIMEOUT: Duration = Duration::from_secs(120);
/// Logical bytes retained under the clone root, including Git objects.
pub(crate) const REMOTE_CLONE_MAX_BYTES: u64 = 512 * 1024 * 1024;
// Account for directory entries and empty files so a highly compressible tree
// cannot evade the byte budget by exhausting filesystem metadata instead.
const REMOTE_CLONE_ENTRY_OVERHEAD_BYTES: u64 = 4 * 1024;
const REMOTE_CLONE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_GIT_OUTPUT_BYTES: u64 = 8 * 1024;
const MAX_GIT_INDEX_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REMOTE_TRACKED_FILES: usize = 10_000;
const GITHUB_PREFIX: &str = "https://github.com/";

#[derive(Debug)]
pub(crate) struct RemoteRepository {
    pub(crate) path: PathBuf,
    pub(crate) canonical_origin: String,
    pub(crate) commit_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitHubRepository {
    owner: String,
    repository: String,
}

impl GitHubRepository {
    fn parse(value: &str) -> std::result::Result<Self, &'static str> {
        if !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err("URL must contain printable ASCII only");
        }
        if value.contains('%') {
            return Err("percent-encoding is not allowed");
        }
        if value.contains('?') || value.contains('#') {
            return Err("query strings and fragments are not allowed");
        }
        let path = value
            .strip_prefix(GITHUB_PREFIX)
            .ok_or("only HTTPS github.com URLs are allowed")?;
        if path.contains('@') || path.contains(':') {
            return Err("userinfo and ports are not allowed");
        }

        let mut components = path.split('/');
        let owner = components.next().unwrap_or_default();
        let repository_with_suffix = components.next().unwrap_or_default();
        if components.next().is_some() || owner.is_empty() || repository_with_suffix.is_empty() {
            return Err("URL must contain exactly an owner and repository");
        }
        let repository = repository_with_suffix
            .strip_suffix(".git")
            .unwrap_or(repository_with_suffix);
        if repository.is_empty() {
            return Err("repository name is empty");
        }

        if owner.len() > 39
            || !owner
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || owner.starts_with('-')
            || owner.ends_with('-')
            || owner.contains("--")
        {
            return Err("owner is outside the GitHub allowlist grammar");
        }
        if repository.len() > 100
            || matches!(repository, "." | "..")
            || !repository
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err("repository is outside the GitHub allowlist grammar");
        }

        Ok(Self {
            owner: owner.to_string(),
            repository: repository.to_string(),
        })
    }

    fn canonical_origin(&self) -> String {
        format!("{GITHUB_PREFIX}{}/{}", self.owner, self.repository)
    }
}

#[derive(Debug, Clone, Copy)]
struct CloneLimits {
    timeout: Duration,
    max_bytes: u64,
    poll_interval: Duration,
}

impl Default for CloneLimits {
    fn default() -> Self {
        Self {
            timeout: REMOTE_CLONE_TIMEOUT,
            max_bytes: REMOTE_CLONE_MAX_BYTES,
            poll_interval: REMOTE_CLONE_POLL_INTERVAL,
        }
    }
}

#[derive(Debug, Clone)]
struct GitProgram {
    executable: PathBuf,
    prefix_args: Vec<OsString>,
    extra_environment: Vec<(OsString, OsString)>,
}

impl Default for GitProgram {
    fn default() -> Self {
        Self {
            executable: PathBuf::from("git"),
            prefix_args: Vec::new(),
            extra_environment: Vec::new(),
        }
    }
}

/// Returns true for input that is trying to select a remote transport. Such an
/// input must never fall back to local-path handling after allowlist rejection.
pub(crate) fn looks_like_remote_target(target: &str) -> bool {
    target.contains("://") || target.starts_with("git@") || target.starts_with("github.com/")
}

pub(crate) fn clone_github_repository(target: &str, clone_dir: &Path) -> Result<RemoteRepository> {
    clone_github_repository_with(
        target,
        clone_dir,
        &GitProgram::default(),
        CloneLimits::default(),
    )
}

fn clone_github_repository_with(
    target: &str,
    clone_dir: &Path,
    git: &GitProgram,
    limits: CloneLimits,
) -> Result<RemoteRepository> {
    let requested = GitHubRepository::parse(target).map_err(blocked_url)?;
    if limits.timeout.is_zero() || limits.max_bytes == 0 || limits.poll_interval.is_zero() {
        return Err(blocked("remote clone limits are invalid"));
    }
    if fs::symlink_metadata(clone_dir).is_ok() {
        return Err(blocked("remote clone destination already exists"));
    }
    let clone_parent = clone_dir
        .parent()
        .ok_or_else(|| blocked("remote clone destination has no parent"))?;
    fs::create_dir_all(clone_parent)
        .map_err(|_| blocked("remote clone parent could not be created"))?;
    let mut cleanup = CloneCleanup::new(clone_dir);
    fs::create_dir(clone_dir)
        .map_err(|_| blocked("remote clone destination could not be created"))?;
    ensure_plain_directory(clone_dir)?;

    // An OS-temporary control directory prevents the caller's repository from
    // contributing local Git config and supplies an intentionally empty hook
    // template. It is removed automatically after acquisition.
    let control = tempfile::tempdir()
        .map_err(|_| blocked("remote clone control directory could not be created"))?;
    let template_dir = control.path().join("empty-template");
    fs::create_dir(&template_dir)
        .map_err(|_| blocked("remote clone template directory could not be created"))?;

    let started = Instant::now();
    let deadline = started
        .checked_add(limits.timeout)
        .ok_or_else(|| blocked("remote clone timeout is invalid"))?;

    let mut command = hardened_git_command(git, control.path(), &template_dir);
    command
        .args(["clone", "--depth=1", "--single-branch", "--no-tags"])
        .arg("--no-recurse-submodules")
        .arg(format!("--template={}", template_dir.display()))
        .arg("--")
        .arg(requested.canonical_origin())
        .arg(clone_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_process_group(&mut command);

    let mut child = command
        .spawn()
        .map_err(|_| blocked("remote clone could not start git"))?;
    let status = wait_for_clone(&mut child, clone_dir, deadline, limits)?;
    if !status.success() {
        return Err(blocked("remote clone git process failed"));
    }
    enforce_size_bound(clone_dir, limits.max_bytes)?;
    ensure_plain_directory(clone_dir)?;
    ensure_plain_directory(&clone_dir.join(".git"))?;

    let fetch_origin = run_git_output(
        git,
        control.path(),
        &template_dir,
        clone_dir,
        ["remote", "get-url", "--all", "origin"],
        deadline,
        limits.poll_interval,
    )?;
    let push_origin = run_git_output(
        git,
        control.path(),
        &template_dir,
        clone_dir,
        ["remote", "get-url", "--push", "--all", "origin"],
        deadline,
        limits.poll_interval,
    )?;
    let fetch_origin = one_output_line(&fetch_origin)
        .and_then(|value| GitHubRepository::parse(value).ok())
        .ok_or_else(|| blocked("remote clone origin is not canonical GitHub HTTPS"))?;
    let push_origin = one_output_line(&push_origin)
        .and_then(|value| GitHubRepository::parse(value).ok())
        .ok_or_else(|| blocked("remote clone push origin is not canonical GitHub HTTPS"))?;
    if fetch_origin != requested || push_origin != requested {
        return Err(blocked(
            "remote clone origin does not match the requested repository",
        ));
    }

    let sha = run_git_output(
        git,
        control.path(),
        &template_dir,
        clone_dir,
        ["rev-parse", "--verify", "HEAD^{commit}"],
        deadline,
        limits.poll_interval,
    )?;
    let sha = one_output_line(&sha)
        .filter(|value| is_lower_hex_sha(value))
        .ok_or_else(|| blocked("remote clone did not resolve an exact 40-hex commit"))?
        .to_string();

    let status = run_git_output(
        git,
        control.path(),
        &template_dir,
        clone_dir,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        deadline,
        limits.poll_interval,
    )?;
    if !status.is_empty() {
        return Err(blocked("remote clone worktree is not clean"));
    }
    if fs::symlink_metadata(clone_dir.join(".git").join("modules")).is_ok() {
        return Err(blocked("remote clone unexpectedly initialized submodules"));
    }
    let index = run_git_output_bounded(
        git,
        control.path(),
        &template_dir,
        clone_dir,
        ["ls-files", "--stage", "-z"],
        deadline,
        limits.poll_interval,
        MAX_GIT_INDEX_OUTPUT_BYTES,
    )?;
    validate_tracked_source(clone_dir, &index)?;
    validate_plain_worktree(clone_dir)?;
    enforce_size_bound(clone_dir, limits.max_bytes)?;

    cleanup.keep();
    Ok(RemoteRepository {
        path: clone_dir.to_path_buf(),
        canonical_origin: requested.canonical_origin(),
        commit_sha: sha,
    })
}

fn hardened_git_command(git: &GitProgram, control_dir: &Path, hooks_dir: &Path) -> Command {
    let mut command = Command::new(&git.executable);
    command
        .args(&git.prefix_args)
        .envs(git.extra_environment.iter().cloned());

    // Never inherit repository redirection, config injection, credentials, or
    // programs that could turn checkout into host-side target-code execution.
    for name in [
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_ASKPASS",
        "GIT_COMMON_DIR",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_DIR",
        "GIT_EXEC_PATH",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_REPLACE_REF_BASE",
        "GIT_SHALLOW_FILE",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_SSL_NO_VERIFY",
        "GIT_TEMPLATE_DIR",
        "GIT_TRACE",
        "GIT_TRACE2",
        "GIT_TRACE2_EVENT",
        "GIT_TRACE2_PERF",
        "GIT_TRACE_CURL",
        "GIT_TRACE_PACKET",
        "GIT_TRACE_PERFORMANCE",
        "GIT_TRACE_SETUP",
        "GIT_WORK_TREE",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "NETRC",
        "SSH_ASKPASS",
        "USERPROFILE",
        "XDG_CONFIG_HOME",
    ] {
        command.env_remove(name);
    }
    // Clear every command-line config tuple an embedding process may have set.
    for index in 0..64 {
        command.env_remove(format!("GIT_CONFIG_KEY_{index}"));
        command.env_remove(format!("GIT_CONFIG_VALUE_{index}"));
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null_device())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GCM_INTERACTIVE", "Never")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .env("GIT_ASKPASS", control_dir.join("askpass-disabled"))
        .env("SSH_ASKPASS", control_dir.join("askpass-disabled"))
        .current_dir(control_dir)
        .arg("--no-replace-objects")
        .args(["-c", "credential.helper="])
        .args(["-c", "credential.interactive=false"])
        .args(["-c", "core.askPass="])
        .arg("-c")
        .arg(format!("core.hooksPath={}", hooks_dir.display()))
        .args(["-c", "core.fsmonitor=false"])
        .args(["-c", "core.untrackedCache=false"])
        .args(["-c", "core.fileMode=true"])
        .arg("-c")
        .arg(format!("core.attributesFile={}", null_device()))
        .args(["-c", "filter.lfs.smudge="])
        .args(["-c", "filter.lfs.required=false"])
        .args(["-c", "http.extraHeader="])
        .args(["-c", "http.followRedirects=false"])
        .args(["-c", "http.sslVerify=true"])
        .args(["-c", "protocol.ext.allow=never"])
        .args(["-c", "protocol.file.allow=never"]);
    command
}

fn run_git_output<I, S>(
    git: &GitProgram,
    control_dir: &Path,
    hooks_dir: &Path,
    repository: &Path,
    args: I,
    deadline: Instant,
    poll_interval: Duration,
) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_git_output_bounded(
        git,
        control_dir,
        hooks_dir,
        repository,
        args,
        deadline,
        poll_interval,
        MAX_GIT_OUTPUT_BYTES,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_git_output_bounded<I, S>(
    git: &GitProgram,
    control_dir: &Path,
    hooks_dir: &Path,
    repository: &Path,
    args: I,
    deadline: Instant,
    poll_interval: Duration,
    max_output_bytes: u64,
) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut output = NamedTempFile::new_in(control_dir)
        .map_err(|_| blocked("remote clone inspection output could not be created"))?;
    let stdout = output
        .reopen()
        .map_err(|_| blocked("remote clone inspection output could not be opened"))?;
    let mut command = hardened_git_command(git, control_dir, hooks_dir);
    command
        .args(["-C"])
        .arg(repository)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::null());
    configure_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|_| blocked("remote clone inspection could not start git"))?;
    let status = wait_for_process(&mut child, deadline, poll_interval)?;
    if !status.success() {
        return Err(blocked("remote clone inspection failed"));
    }
    let length = output
        .as_file()
        .metadata()
        .map_err(|_| blocked("remote clone inspection output could not be inspected"))?
        .len();
    if length > max_output_bytes {
        return Err(blocked("remote clone inspection output exceeded its bound"));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    output
        .as_file_mut()
        .read_to_end(&mut bytes)
        .map_err(|_| blocked("remote clone inspection output could not be read"))?;
    Ok(bytes)
}

fn validate_tracked_source(clone_dir: &Path, index: &[u8]) -> Result<()> {
    let records: Vec<&[u8]> = if index.contains(&0) {
        if index.last() != Some(&0) {
            return Err(blocked("remote clone index output is malformed"));
        }
        index[..index.len().saturating_sub(1)]
            .split(|byte| *byte == 0)
            .collect()
    } else if index.is_empty() {
        Vec::new()
    } else {
        // Test doubles and older embedding shims may return one record without
        // the requested NUL terminator. Multiple newline-delimited records are
        // never accepted because path controls are rejected below.
        vec![index]
    };
    if records.len() > MAX_REMOTE_TRACKED_FILES {
        return Err(blocked("remote clone has too many tracked files"));
    }

    for record in records {
        let record = std::str::from_utf8(record)
            .map_err(|_| blocked("remote clone index contains a non-UTF-8 path"))?;
        let (metadata, relative) = record
            .split_once('\t')
            .or_else(|| {
                (!index.contains(&0))
                    .then(|| record.split_once("\\t"))
                    .flatten()
            })
            .ok_or_else(|| blocked("remote clone index output is malformed"))?;
        if relative.is_empty()
            || relative
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\\')
        {
            return Err(blocked("remote clone index contains an unsafe path"));
        }
        let mut fields = metadata.split_ascii_whitespace();
        let mode = fields.next().unwrap_or_default();
        let object = fields.next().unwrap_or_default();
        let stage = fields.next().unwrap_or_default();
        if fields.next().is_some()
            || object.len() != 40
            || !object.bytes().all(|byte| byte.is_ascii_hexdigit())
            || stage != "0"
        {
            return Err(blocked("remote clone index identity is malformed"));
        }
        match mode {
            "100644" => {}
            "100755" if cfg!(unix) => {}
            "100755" => {
                return Err(blocked(
                    "remote clone executable Git mode 100755 cannot be preserved on this host",
                ))
            }
            "120000" => return Err(blocked("remote clone contains a tracked symbolic link")),
            "160000" => return Err(blocked("remote clone contains a gitlink submodule")),
            _ => {
                return Err(blocked(
                    "remote clone contains an unsupported tracked entry",
                ))
            }
        }

        let path = clone_dir.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| blocked("remote clone tracked file is missing from the worktree"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(blocked("remote clone tracked source is not a regular file"));
        }
        if relative == ".lfsconfig" {
            return Err(blocked(
                "remote clone contains repository-local LFS configuration",
            ));
        }
        if is_lfs_pointer(&path)? {
            return Err(blocked(
                "remote clone contains an unresolved Git LFS pointer",
            ));
        }
        if relative == ".gitattributes" && declares_lfs_filter(&path)? {
            return Err(blocked("remote clone declares Git LFS-managed source"));
        }
    }
    Ok(())
}

fn is_lfs_pointer(path: &Path) -> Result<bool> {
    const LFS_HEADER: &[u8] = b"version https://git-lfs.github.com/spec/v1";
    let mut file = fs::File::open(path)
        .map_err(|_| blocked("remote clone tracked file could not be inspected"))?;
    let mut prefix = [0u8; 64];
    let read = file
        .read(&mut prefix)
        .map_err(|_| blocked("remote clone tracked file could not be inspected"))?;
    Ok(prefix[..read].starts_with(LFS_HEADER))
}

fn declares_lfs_filter(path: &Path) -> Result<bool> {
    const MAX_ATTRIBUTES_BYTES: u64 = 1024 * 1024;
    let metadata = fs::metadata(path)
        .map_err(|_| blocked("remote clone attributes could not be inspected"))?;
    if metadata.len() > MAX_ATTRIBUTES_BYTES {
        return Err(blocked("remote clone attributes exceeded their byte bound"));
    }
    let bytes =
        fs::read(path).map_err(|_| blocked("remote clone attributes could not be inspected"))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| blocked("remote clone attributes are not UTF-8"))?;
    Ok(text.lines().any(|line| {
        let normalized: String = line
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(|byte| byte.to_ascii_lowercase() as char)
            .collect();
        normalized.contains("filter=lfs")
    }))
}

fn validate_plain_worktree(clone_dir: &Path) -> Result<()> {
    for entry in WalkDir::new(clone_dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| entry.depth() == 0 || entry.file_name() != OsStr::new(".git"))
    {
        let entry = entry.map_err(|_| blocked("remote clone worktree could not be inspected"))?;
        if entry.depth() == 0 {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| blocked("remote clone worktree could not be inspected"))?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(blocked("remote clone contains a link or reparse entry"));
        }
        if !metadata.is_dir() && !metadata.is_file() {
            return Err(blocked("remote clone contains a non-regular entry"));
        }
    }
    Ok(())
}

fn wait_for_clone(
    child: &mut Child,
    clone_dir: &Path,
    deadline: Instant,
    limits: CloneLimits,
) -> Result<ExitStatus> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| blocked("remote clone process could not be inspected"))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            terminate_process_tree(child);
            return Err(blocked("remote clone exceeded its time bound"));
        }
        match directory_accounted_bytes(clone_dir, limits.max_bytes) {
            Ok(bytes) if bytes > limits.max_bytes => {
                terminate_process_tree(child);
                return Err(blocked("remote clone exceeded its byte bound"));
            }
            Ok(_) => {}
            Err(()) => {
                terminate_process_tree(child);
                return Err(blocked("remote clone size could not be inspected"));
            }
        }
        sleep_until_next_poll(deadline, limits.poll_interval);
    }
}

fn wait_for_process(
    child: &mut Child,
    deadline: Instant,
    poll_interval: Duration,
) -> Result<ExitStatus> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| blocked("remote clone inspection process could not be inspected"))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            terminate_process_tree(child);
            return Err(blocked("remote clone exceeded its time bound"));
        }
        sleep_until_next_poll(deadline, poll_interval);
    }
}

fn sleep_until_next_poll(deadline: Instant, poll_interval: Duration) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if !remaining.is_zero() {
        thread::sleep(poll_interval.min(remaining));
    }
}

fn directory_accounted_bytes(root: &Path, stop_after: u64) -> std::result::Result<u64, ()> {
    if !root.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error)
                if error
                    .io_error()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                // Git atomically renames temporary packfiles while we measure.
                continue;
            }
            Err(_) => return Err(()),
        };
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(()),
        };
        total = total
            .checked_add(REMOTE_CLONE_ENTRY_OVERHEAD_BYTES)
            .ok_or(())?;
        if metadata.is_file() {
            total = total.checked_add(metadata.len()).ok_or(())?;
        }
        if total > stop_after {
            return Ok(total);
        }
    }
    Ok(total)
}

fn enforce_size_bound(root: &Path, max_bytes: u64) -> Result<()> {
    match directory_accounted_bytes(root, max_bytes) {
        Ok(bytes) if bytes <= max_bytes => Ok(()),
        Ok(_) => Err(blocked("remote clone exceeded its byte bound")),
        Err(()) => Err(blocked("remote clone size could not be inspected")),
    }
}

fn ensure_plain_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| blocked("remote clone destination could not be inspected"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(blocked("remote clone destination is not a plain directory"));
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn one_output_line(bytes: &[u8]) -> Option<&str> {
    let value = std::str::from_utf8(bytes).ok()?;
    let value = value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value);
    if value.is_empty() || value.contains(['\r', '\n']) {
        None
    } else {
        Some(value)
    }
}

fn is_lower_hex_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn blocked_url(reason: &'static str) -> RunnerError {
    RunnerError::Msg(format!("BLOCKED: remote target rejected: {reason}"))
}

fn blocked(message: &'static str) -> RunnerError {
    RunnerError::Msg(format!("BLOCKED: {message}"))
}

struct CloneCleanup<'a> {
    path: &'a Path,
    remove: bool,
}

impl<'a> CloneCleanup<'a> {
    fn new(path: &'a Path) -> Self {
        Self { path, remove: true }
    }

    fn keep(&mut self) {
        self.remove = false;
    }
}

impl Drop for CloneCleanup<'_> {
    fn drop(&mut self) {
        if !self.remove {
            return;
        }
        let Ok(metadata) = fs::symlink_metadata(self.path) else {
            return;
        };
        if metadata.is_dir() && !metadata.file_type().is_symlink() && !is_reparse_point(&metadata) {
            let _ = fs::remove_dir_all(self.path);
        } else {
            let _ = fs::remove_file(self.path);
        }
    }
}

#[cfg(unix)]
fn null_device() -> &'static str {
    "/dev/null"
}

#[cfg(windows)]
fn null_device() -> &'static str {
    "NUL"
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(windows)]
fn configure_process_group(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

#[cfg(unix)]
fn terminate_process_tree(child: &mut Child) {
    let pid = child.id();
    // SAFETY: the child was started as the leader of a fresh process group;
    // the negative PID therefore targets only that bounded Git invocation.
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(windows)]
fn terminate_process_tree(child: &mut Child) {
    let pid = child.id().to_string();
    let _ = Command::new("taskkill.exe")
        .args(["/PID", &pid, "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::{tempdir, TempDir};

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn github_url_allowlist_is_exact() {
        for accepted in [
            "https://github.com/owner/repo",
            "https://github.com/owner/repo.git",
            "https://github.com/acme-inc/.github",
        ] {
            let result = GitHubRepository::parse(accepted);
            assert!(
                result.is_ok(),
                "unexpectedly rejected {accepted}: {result:?}"
            );
        }

        for rejected in [
            "http://github.com/owner/repo",
            "https://user@github.com/owner/repo",
            "https://github.com:443/owner/repo",
            "https://github.com/owner/repo/extra",
            "https://github.com/owner/repo/",
            "https://github.com/owner/repo?ref=main",
            "https://github.com/owner/repo#readme",
            "https://github.com/owner%2frepo",
            "https://github.com/owner/repo%2egit",
            "https://github.com/owner/..",
            "https://github.com/-owner/repo",
            "https://github.com/owner--name/repo",
            "https://github.com/Owner_Reject/repo",
            "https://github.com/owner/.git",
            "HTTPS://github.com/owner/repo",
            "git@github.com:owner/repo.git",
            "ssh://github.com/owner/repo.git",
            "https://github.com/owner/repo\nnext",
        ] {
            assert!(
                GitHubRepository::parse(rejected).is_err(),
                "unexpectedly accepted {rejected:?}"
            );
        }
    }

    #[test]
    fn remote_syntax_cannot_fall_back_to_a_local_path() {
        for target in [
            "http://github.com/owner/repo",
            "ssh://github.com/owner/repo",
            "git@github.com:owner/repo",
            "github.com/owner/repo",
        ] {
            assert!(looks_like_remote_target(target));
        }
        assert!(!looks_like_remote_target("./github.com/owner/repo"));
    }

    #[test]
    fn successful_clone_is_canonical_clean_and_exact() {
        let fixture = FakeGit::new("success");
        let destination = fixture.root.path().join("clone");
        let repository = clone_github_repository_with(
            "https://github.com/owner/repo.git",
            &destination,
            &fixture.program,
            test_limits(),
        )
        .unwrap();

        assert_eq!(repository.path, destination);
        assert_eq!(repository.canonical_origin, "https://github.com/owner/repo");
        assert_eq!(repository.commit_sha, SHA);
        assert!(repository.path.is_dir());
    }

    #[test]
    fn clone_command_disables_redirects_credentials_submodules_and_lfs() {
        let mut fixture = FakeGit::new("success");
        fixture.program.extra_environment.extend([
            (OsString::from("GIT_CONFIG_COUNT"), OsString::from("1")),
            (
                OsString::from("GIT_CONFIG_KEY_0"),
                OsString::from("http.extraHeader"),
            ),
            (
                OsString::from("GIT_CONFIG_VALUE_0"),
                OsString::from("Authorization: secret"),
            ),
            (OsString::from("GIT_SSL_NO_VERIFY"), OsString::from("1")),
        ]);
        let destination = fixture.root.path().join("clone");
        clone_github_repository_with(
            "https://github.com/owner/repo",
            &destination,
            &fixture.program,
            test_limits(),
        )
        .unwrap();

        let log = fs::read_to_string(&fixture.log).unwrap();
        assert!(log.contains("http.followRedirects=false"));
        assert!(log.contains("http.sslVerify=true"));
        assert!(log.contains("credential.helper="));
        assert!(log.contains("http.extraHeader="));
        assert!(log.contains("filter.lfs.smudge="));
        assert!(log.contains("filter.lfs.required=false"));
        assert!(log.contains("protocol.file.allow=never"));
        assert!(log.contains("--no-recurse-submodules"));
        assert!(log.contains("--no-replace-objects"));
        assert!(log.contains("core.fsmonitor=false"));
        assert!(log.contains("core.untrackedCache=false"));
        assert!(log.contains("core.hooksPath="));
        assert!(log.contains("PROMPT=0"));
        assert!(log.contains("GCM=Never"));
        assert!(log.contains("LFS=1"));
        assert!(log.contains("CONFIG_COUNT="));
        assert!(log.contains("CONFIG_KEY_0="));
        assert!(log.contains("CONFIG_VALUE_0="));
        assert!(log.contains("SSL_NO_VERIFY="));
        assert!(!log.contains("Authorization: secret"));
    }

    #[cfg(not(unix))]
    #[test]
    fn real_git_executable_index_entry_is_rejected_on_non_unix() {
        let root = tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        let init = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repository)
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        fs::write(repository.join("script"), b"echo exact\n").unwrap();
        for args in [
            &["add", "--", "script"][..],
            &["update-index", "--chmod=+x", "--", "script"][..],
        ] {
            let output = Command::new("git")
                .args(args)
                .current_dir(&repository)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let index = Command::new("git")
            .args(["ls-files", "--stage", "-z"])
            .current_dir(&repository)
            .output()
            .unwrap();
        assert!(index.status.success());
        assert!(index.stdout.starts_with(b"100755 "));

        let error = validate_tracked_source(&repository, &index.stdout)
            .unwrap_err()
            .to_string();
        assert!(error.contains("100755 cannot be preserved"), "{error}");
    }

    #[test]
    fn timeout_kills_git_and_removes_partial_clone() {
        let fixture = FakeGit::new("timeout");
        let destination = fixture.root.path().join("clone");
        let started = Instant::now();
        let error = clone_github_repository_with(
            "https://github.com/owner/repo",
            &destination,
            &fixture.program,
            CloneLimits {
                timeout: Duration::from_millis(250),
                max_bytes: 2 * 1024 * 1024,
                poll_interval: Duration::from_millis(10),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("time bound"), "unexpected error: {error}");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!destination.exists());
    }

    #[test]
    fn size_bound_kills_git_and_removes_partial_clone() {
        let fixture = FakeGit::new("size");
        let destination = fixture.root.path().join("clone");
        let error = clone_github_repository_with(
            "https://github.com/owner/repo",
            &destination,
            &fixture.program,
            CloneLimits {
                timeout: Duration::from_secs(5),
                max_bytes: 64 * 1024,
                poll_interval: Duration::from_millis(10),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("byte bound"), "unexpected error: {error}");
        assert!(!destination.exists());
    }

    #[test]
    fn mismatched_origin_bad_sha_dirty_tree_and_unsupported_source_are_rejected() {
        for (mode, expected) in [
            ("origin-mismatch", "origin does not match"),
            ("bad-sha", "exact 40-hex commit"),
            ("dirty", "worktree is not clean"),
            ("submodule", "initialized submodules"),
            ("gitlink", "gitlink submodule"),
            ("symlink-index", "tracked symbolic link"),
            ("lfs", "unresolved Git LFS pointer"),
            ("lfs-attributes", "declares Git LFS-managed source"),
        ] {
            let fixture = FakeGit::new(mode);
            let destination = fixture.root.path().join("clone");
            let error = clone_github_repository_with(
                "https://github.com/owner/repo",
                &destination,
                &fixture.program,
                test_limits(),
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains(expected),
                "{mode}: unexpected error: {error}"
            );
            assert!(!destination.exists(), "{mode}: partial clone remained");
        }
    }

    #[test]
    fn hostile_invalid_url_is_not_reflected_in_terminal_error() {
        let fixture = FakeGit::new("success");
        let hostile = "https://github.com/owner/repo?token=super-secret\u{1b}[2J";
        let error = clone_github_repository_with(
            hostile,
            &fixture.root.path().join("clone"),
            &fixture.program,
            test_limits(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.starts_with("BLOCKED:"));
        assert!(!error.contains("super-secret"));
        assert!(!error.contains('\u{1b}'));
    }

    fn test_limits() -> CloneLimits {
        CloneLimits {
            // Full runner tests intentionally exercise several real/fake Git
            // processes in parallel; leave scheduling headroom while the
            // dedicated timeout tests retain their millisecond deadline.
            timeout: Duration::from_secs(15),
            max_bytes: 2 * 1024 * 1024,
            poll_interval: Duration::from_millis(10),
        }
    }

    struct FakeGit {
        root: TempDir,
        log: PathBuf,
        program: GitProgram,
    }

    impl FakeGit {
        fn new(mode: &str) -> Self {
            let root = tempdir().unwrap();
            let log = root.path().join("git.log");
            let clone_dir = root.path().join("clone");
            let (executable, prefix_args) = write_fake_git(root.path());
            let program = GitProgram {
                executable,
                prefix_args,
                extra_environment: vec![
                    (OsString::from("FAKE_GIT_MODE"), OsString::from(mode)),
                    (
                        OsString::from("FAKE_GIT_LOG"),
                        log.as_os_str().to_os_string(),
                    ),
                    (
                        OsString::from("FAKE_CLONE_DIR"),
                        clone_dir.as_os_str().to_os_string(),
                    ),
                    (
                        OsString::from("FAKE_ORIGIN"),
                        OsString::from("https://github.com/owner/repo.git"),
                    ),
                    (OsString::from("FAKE_SHA"), OsString::from(SHA)),
                ],
            };
            Self { root, log, program }
        }
    }

    #[cfg(unix)]
    fn write_fake_git(root: &Path) -> (PathBuf, Vec<OsString>) {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join("fake-git.sh");
        fs::write(
            &path,
            r##"#!/bin/sh
set -eu
{
  printf 'ARGS='
  printf '%s|' "$@"
  printf '\nPROMPT=%s\nGCM=%s\nLFS=%s\nCONFIG_COUNT=%s\nCONFIG_KEY_0=%s\nCONFIG_VALUE_0=%s\nSSL_NO_VERIFY=%s\n' \
    "${GIT_TERMINAL_PROMPT-}" "${GCM_INTERACTIVE-}" "${GIT_LFS_SKIP_SMUDGE-}" \
    "${GIT_CONFIG_COUNT-}" "${GIT_CONFIG_KEY_0-}" "${GIT_CONFIG_VALUE_0-}" "${GIT_SSL_NO_VERIFY-}"
} >> "$FAKE_GIT_LOG"
operation=''
for argument in "$@"; do
  case "$argument" in
    clone|remote|rev-parse|status|ls-files) operation="$argument" ;;
  esac
done
case "$operation" in
  clone)
    mkdir -p "$FAKE_CLONE_DIR/.git"
    printf '%s\n' tracked > "$FAKE_CLONE_DIR/README.md"
    case "$FAKE_GIT_MODE" in
      timeout) sleep 30 ;;
      size) dd if=/dev/zero of="$FAKE_CLONE_DIR/large.bin" bs=1048576 count=1 2>/dev/null; sleep 30 ;;
      submodule) mkdir -p "$FAKE_CLONE_DIR/.git/modules" ;;
      lfs) printf '%s\n%s\n%s\n' 'version https://git-lfs.github.com/spec/v1' 'oid sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' 'size 1' > "$FAKE_CLONE_DIR/README.md" ;;
      lfs-attributes) printf '%s\n' '*.bin filter = lfs diff=lfs' > "$FAKE_CLONE_DIR/.gitattributes" ;;
    esac
    ;;
  remote)
    if [ "$FAKE_GIT_MODE" = origin-mismatch ]; then
      printf '%s\n' 'https://github.com/other/repo.git'
    else
      printf '%s\n' "$FAKE_ORIGIN"
    fi
    ;;
  rev-parse)
    if [ "$FAKE_GIT_MODE" = bad-sha ]; then printf '%s\n' BAD; else printf '%s\n' "$FAKE_SHA"; fi
    ;;
  status)
    if [ "$FAKE_GIT_MODE" = dirty ]; then printf '%s\n' ' M tracked'; fi
    ;;
  ls-files)
    case "$FAKE_GIT_MODE" in
      gitlink) printf '160000 %s 0\tsubmodule\0' "$FAKE_SHA" ;;
      symlink-index) printf '120000 %s 0\tlink\0' "$FAKE_SHA" ;;
      lfs-attributes) printf '100644 %s 0\t.gitattributes\0' "$FAKE_SHA" ;;
      *) printf '100644 %s 0\tREADME.md\0' "$FAKE_SHA" ;;
    esac
    ;;
esac
"##,
        )
        .unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        (path, Vec::new())
    }

    #[cfg(windows)]
    fn write_fake_git(root: &Path) -> (PathBuf, Vec<OsString>) {
        let path = root.join("fake-git.cmd");
        fs::write(
            &path,
            r##"@echo off
setlocal
>>"%FAKE_GIT_LOG%" echo ARGS=%*
>>"%FAKE_GIT_LOG%" echo PROMPT=%GIT_TERMINAL_PROMPT%
>>"%FAKE_GIT_LOG%" echo GCM=%GCM_INTERACTIVE%
>>"%FAKE_GIT_LOG%" echo LFS=%GIT_LFS_SKIP_SMUDGE%
>>"%FAKE_GIT_LOG%" echo CONFIG_COUNT=%GIT_CONFIG_COUNT%
>>"%FAKE_GIT_LOG%" echo CONFIG_KEY_0=%GIT_CONFIG_KEY_0%
>>"%FAKE_GIT_LOG%" echo CONFIG_VALUE_0=%GIT_CONFIG_VALUE_0%
>>"%FAKE_GIT_LOG%" echo SSL_NO_VERIFY=%GIT_SSL_NO_VERIFY%
set "operation="
:parse
if "%~1"=="" goto dispatch
if "%~1"=="clone" set "operation=clone"
if "%~1"=="remote" set "operation=remote"
if "%~1"=="rev-parse" set "operation=rev-parse"
if "%~1"=="status" set "operation=status"
if "%~1"=="ls-files" set "operation=lsfiles"
shift
goto parse
:dispatch
if "%operation%"=="clone" goto clone
if "%operation%"=="remote" goto remote
if "%operation%"=="rev-parse" goto revparse
if "%operation%"=="status" goto status
if "%operation%"=="lsfiles" goto lsfiles
exit /b 2
:clone
mkdir "%FAKE_CLONE_DIR%\.git" 2>nul
>"%FAKE_CLONE_DIR%\README.md" echo tracked
if "%FAKE_GIT_MODE%"=="submodule" mkdir "%FAKE_CLONE_DIR%\.git\modules" 2>nul
if "%FAKE_GIT_MODE%"=="lfs" >"%FAKE_CLONE_DIR%\README.md" echo version https://git-lfs.github.com/spec/v1
if "%FAKE_GIT_MODE%"=="lfs-attributes" >"%FAKE_CLONE_DIR%\.gitattributes" echo *.bin filter = lfs diff=lfs
if "%FAKE_GIT_MODE%"=="size" fsutil file createnew "%FAKE_CLONE_DIR%\large.bin" 1048576 >nul
if "%FAKE_GIT_MODE%"=="timeout" ping 127.0.0.1 -n 31 >nul
if "%FAKE_GIT_MODE%"=="size" ping 127.0.0.1 -n 31 >nul
exit /b 0
:remote
if "%FAKE_GIT_MODE%"=="origin-mismatch" echo https://github.com/other/repo.git
if not "%FAKE_GIT_MODE%"=="origin-mismatch" echo %FAKE_ORIGIN%
exit /b 0
:revparse
if "%FAKE_GIT_MODE%"=="bad-sha" echo BAD
if not "%FAKE_GIT_MODE%"=="bad-sha" echo %FAKE_SHA%
exit /b 0
:status
if "%FAKE_GIT_MODE%"=="dirty" echo  M tracked
exit /b 0
:lsfiles
if "%FAKE_GIT_MODE%"=="gitlink" <nul set /p "=160000 %FAKE_SHA% 0	submodule"
if "%FAKE_GIT_MODE%"=="symlink-index" <nul set /p "=120000 %FAKE_SHA% 0	link"
if "%FAKE_GIT_MODE%"=="lfs-attributes" <nul set /p "=100644 %FAKE_SHA% 0	.gitattributes"
if not "%FAKE_GIT_MODE%"=="gitlink" if not "%FAKE_GIT_MODE%"=="symlink-index" if not "%FAKE_GIT_MODE%"=="lfs-attributes" <nul set /p "=100644 %FAKE_SHA% 0	README.md"
exit /b 0
"##,
        )
        .unwrap();
        (path, Vec::new())
    }
}
