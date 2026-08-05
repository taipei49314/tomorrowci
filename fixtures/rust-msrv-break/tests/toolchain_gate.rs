//! Fails on rustc beta/nightly channels (deterministic channel-based break).
//! Passes on stable numbered toolchains and "stable".

use std::process::Command;

#[test]
fn rejects_prerelease_toolchains() {
    let out = Command::new("rustc")
        .arg("-vV")
        .output()
        .expect("rustc must be available in the container");
    let text = String::from_utf8_lossy(&out.stdout);
    let release = text
        .lines()
        .find(|l| l.starts_with("release:"))
        .unwrap_or("")
        .to_lowercase();
    assert!(
        !release.contains("beta") && !release.contains("nightly"),
        "toolchain break: prerelease rustc not supported by this fixture: {release}"
    );
}
