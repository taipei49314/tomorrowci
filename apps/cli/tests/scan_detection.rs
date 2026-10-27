use std::process::Command;
use tempfile::tempdir;

#[test]
fn unsupported_repository_exits_nonzero_without_a_detection_pass() {
    let root = tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_tomorrowci"))
        .args(["scan", "."])
        .current_dir(root.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("verdict: UNSUPPORTED"), "{stdout}");
    assert!(!stdout.contains("detection: PASS"), "{stdout}");
    assert!(!root.path().join(".tomorrowci").exists());
}

#[test]
fn requested_ecosystem_cannot_be_reported_as_an_unselected_detected_ecosystem() {
    let root = tempdir().unwrap();
    std::fs::write(root.path().join("requirements.txt"), "").unwrap();
    std::fs::write(
        root.path().join(".tomorrowci.yml"),
        "version: 1\nproject:\n  ecosystem: rust\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_tomorrowci"))
        .args(["scan", "."])
        .current_dir(root.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("no supported rust ecosystem detected"),
        "{stdout}"
    );
    assert!(!stdout.contains("ecosystem: python"), "{stdout}");
    assert!(!stdout.contains("detection: PASS"), "{stdout}");
}
