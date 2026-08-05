//! Fails on rustc newer than the fixture's supported ceiling (1.84.x).
//! Baseline is pinned to 1.83 → PASS; candidates 1.85+ → FUTURE_FAIL.

use std::process::Command;

fn rustc_release() -> String {
    let out = Command::new("rustc")
        .arg("-vV")
        .output()
        .expect("rustc must be available in the container");
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find(|l| l.starts_with("release:"))
        .map(|l| l.trim_start_matches("release:").trim().to_string())
        .unwrap_or_default()
}

fn parse_minor(release: &str) -> (u32, u32) {
    // e.g. "1.85.0" or "1.85.0-nightly"
    let core = release.split('-').next().unwrap_or(release);
    let mut parts = core.split('.');
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor)
}

#[test]
fn rejects_toolchains_newer_than_1_84() {
    let release = rustc_release();
    let (major, minor) = parse_minor(&release);
    assert!(
        major == 1 && minor <= 84,
        "toolchain break: fixture supports rustc <= 1.84, got release={release} (major={major} minor={minor})"
    );
}
