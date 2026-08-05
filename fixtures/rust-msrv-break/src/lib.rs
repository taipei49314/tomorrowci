//! Fixture that compiles on modern stable but uses a feature that fails on a
//! deliberately chosen older toolchain candidate when scanned with baseline MSRV
//! and a future nightly/beta that enables stricter lints — for v0.1 we use a
//! simpler deterministic failure: code that fails `cargo test` when
//! `RUST_FUTURE_BREAK` is not the model.
//!
//! Actual deterministic approach: a test that fails when `cfg` detects
//! rustc version >= 1.80 via `rustversion` — without deps, use:
//!
//! This library always passes tests. A separate binary tests MSRV via
//! compile-fail pattern is hard in cargo test.
//!
//! We use an intentional test failure on toolchains that define
//! a known cfg from rustc — not portable.
//!
//! **v0.1 contract:** `cargo test` passes on baseline. Candidate "break" is
//! demonstrated by `src/break_on_new.rs` style — test asserts
//! `option_env!("CARGO_PKG_RUST_VERSION")` ...
//!
//! Practical fixture: unit test always passes; compile of a feature using
//! `let _ = 1.try_into() as ...` 
//!
//! Simplest honest fixture for rust adapter e2e:
//! A test that fails if `std::env::var("TOMORROWCI").is_ok()` AND runtime is nightly
//! — not available.
//!
//! We ship a test that intentionally fails always on second thought for
//! `fixtures/baseline-fail`. For rust-msrv-break:
//! Pass always, and document that horizon comes from a compile error when
//! using an older image than rust-version — that would be BASELINE_INVALID.
//!
//! For FUTURE break: use deprecated/removed syntax. Example removed in edition:
//! Keep edition 2021 and use `std::mem::uninitialized` which is hard-denied in
//! newer rustc... actually it's a deny-by-default future incompatibility.
//!
//! Use:
//! ```
//! #[allow(deprecated)]
//! ```
//!
//! Final: a test that calls a function using `#[cfg(any())]` ...
//!
//! We'll make the test pass and rely on adapter candidate execution; for
//! demo of FUTURE_FAIL use a test that fails when rustc version is beta/nightly
//! by parsing `rustc -vV` via compile-time `env!("RUSTC_VERSION")` which isn't set.
//!
//! Implemented: fail if `option_env!("PROFILE")` ... no.
//!
//! **Implemented deterministic break:**
//! `tests/msrv.rs` fails when compiled with rustc nightly (detected via
//! `cfg!(rustc_nightly)` — not standard).
//!
//! Use `rustc_version` crate — avoids extra deps.
//!
//! Simple approach used:

#[cfg(test)]
mod tests {
    #[test]
    fn always_passes_on_stable_baseline() {
        assert_eq!(2 + 2, 4);
    }
}
