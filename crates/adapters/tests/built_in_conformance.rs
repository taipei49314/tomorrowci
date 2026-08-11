use tomorrowci_adapter_node::NodeAdapter;
use tomorrowci_adapter_python::PythonAdapter;
use tomorrowci_adapter_rust::RustAdapter;
use tomorrowci_adapters::conformance::{assert_adapter_conforms, AdapterFixture};
use tomorrowci_core::Ecosystem;

#[test]
fn python_builtin_conforms_to_adapter_sdk_v1() {
    let fixture = AdapterFixture::new("python-pip", "python", Ecosystem::Python)
        .file("requirements.txt", "pytest==8.4.2\n")
        .file(
            "pyproject.toml",
            "[project]\nname = \"adapter-conformance\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\n",
        );
    let report = assert_adapter_conforms(&PythonAdapter::new(), &fixture).unwrap();
    assert_eq!(report.checks.len(), 8);
}

#[test]
fn node_builtin_conforms_to_adapter_sdk_v1() {
    let fixture = AdapterFixture::new("node-npm", "node", Ecosystem::Node)
        .file(
            "package.json",
            r#"{"name":"adapter-conformance","version":"0.1.0","engines":{"node":">=20"}}"#,
        )
        .file(
            "package-lock.json",
            r#"{"name":"adapter-conformance","version":"0.1.0","lockfileVersion":3,"packages":{}}"#,
        );
    let report = assert_adapter_conforms(&NodeAdapter::new(), &fixture).unwrap();
    assert_eq!(report.checks.len(), 8);
}

#[test]
fn rust_builtin_conforms_to_adapter_sdk_v1() {
    let fixture = AdapterFixture::new("rust-cargo", "rust", Ecosystem::Rust).file(
        "Cargo.toml",
        "[package]\nname = \"adapter-conformance\"\nversion = \"0.1.0\"\nedition = \"2021\"\nrust-version = \"1.75\"\n",
    );
    let report = assert_adapter_conforms(&RustAdapter::new(), &fixture).unwrap();
    assert_eq!(report.checks.len(), 8);
}
