use tempfile::tempdir;
use tomorrowci_core::Config;
use tomorrowci_runner::{scan_local, ScanOptions};
use tomorrowci_sandbox::make_disposable_copy;

#[test]
fn concrete_dependencies_cannot_silently_reuse_the_baseline_runtime_image() {
    let root = tempdir().unwrap();
    let source =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/dependency-python");
    make_disposable_copy(&source, root.path()).unwrap();
    let mut config = Config::load_file(&root.path().join(".tomorrowci.yml")).unwrap();
    config.candidates.runtime.max_versions = 1;
    let error = scan_local(
        root.path(),
        ScanOptions {
            config,
            allow_scripted: false,
        },
    )
    .err()
    .expect("mixed runtimes must be rejected before container execution");
    assert!(
        error
            .to_string()
            .contains("concrete dependency experiments pin one runtime image"),
        "{error}"
    );
}

#[test]
fn explicit_ecosystem_does_not_fall_back_to_another_detected_manifest() {
    let root = tempdir().unwrap();
    std::fs::write(root.path().join("requirements.txt"), "").unwrap();
    let mut config = Config::default();
    config.project.ecosystem = "rust".into();
    let error = scan_local(
        root.path(),
        ScanOptions {
            config,
            allow_scripted: false,
        },
    )
    .err()
    .expect("explicit Rust cannot fall back to Python");
    assert!(
        error
            .to_string()
            .contains("no supported rust ecosystem detected"),
        "{error}"
    );
    assert!(!root.path().join(".tomorrowci").exists());
}

#[test]
fn auto_detected_node_cannot_ignore_explicit_python_candidates() {
    let root = tempdir().unwrap();
    std::fs::write(
        root.path().join("package.json"),
        "{\"scripts\":{\"test\":\"node test.js\"}}",
    )
    .unwrap();
    let mut config = Config::default();
    config.candidates.runtime.versions = Some(vec!["3.14".into()]);
    let error = scan_local(
        root.path(),
        ScanOptions {
            config,
            allow_scripted: false,
        },
    )
    .err()
    .expect("unsupported explicit candidate list must not be ignored");
    assert!(
        error
            .to_string()
            .contains("currently supported only for Python"),
        "{error}"
    );
    assert!(!root.path().join(".tomorrowci").exists());
}
