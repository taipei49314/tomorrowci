# Adapter SDK contract

TomorrowCI adapter API `1.0` is a versioned, data-only Rust trait contract. The
host negotiates every registered adapter before detection; a schema mismatch,
incompatible version, duplicate capability, missing capability, unknown
capability, or forbidden capability rejects the registry before adapter hooks
run.

## Contract and capabilities

An external adapter implements `tomorrowci_adapters::EcosystemAdapter` and
explicitly returns `AdapterContract::v1()` from `contract()`. API 1.0 requires:

- `detect-project`
- `resolve-baseline`
- `plan-candidates`
- `materialize-sandbox`
- `emit-command-specs`
- `normalize-failure`

The reserved identifiers `host-shell`, `engine-socket`, and `host-secrets` are
always forbidden. Every other unrecognized identifier also fails closed. The
contract JSON uses `deny_unknown_fields`; this host accepts exactly schema 1,
API major 1, and adapter minor versions no newer than its own.

## Security boundary

Adapters return typed descriptions; they receive no SDK capability for a host
shell, container-engine socket, or host environment/secrets. The public safety
validator rejects shell trampolines, engine clients/socket references,
secret-like environment keys, explicit host mounts, full-time network, and
network requests outside `CommandPhase::Fetch`.

An adapter is linked Rust code, so installing an unreviewed binary crate is a
code-trust decision: the trait cannot sandbox arbitrary code inside the crate
itself. Conformance proves declared contract and emitted-data behavior, not the
absence of hidden native side effects. Production distribution must therefore
pin and review adapter source just like any other compiled dependency.

## Conformance and fixture kit

Build a confined disposable fixture with `AdapterFixture`, then call
`assert_adapter_conforms`. The suite checks negotiation and JSON round-trip,
detection, baseline identity, unique candidate identity, sandbox safety,
command safety, and deterministic typed failure normalization.

The three built-in adapters run this exact suite in
`crates/adapters/tests/built_in_conformance.rs`. A copyable external-style
implementation and its conformance test are in `crates/adapter-example`.
