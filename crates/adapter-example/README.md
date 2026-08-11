# Minimal external adapter example

`ExampleAdapter` implements only the public `tomorrowci-adapters` SDK. It
explicitly declares adapter API `1.0`, emits data-only sandbox commands, and
runs the same public conformance suite as the three built-in adapters.

Copy this crate outside the workspace, replace the `path` dependencies with the
published TomorrowCI crate versions, then replace the example detection,
baseline, candidates, and commands. Adapter API v1 has a closed ecosystem
schema, so an alternate adapter must target Python, Node, or Rust; adding a new
ecosystem requires a future core/adapter contract version.
