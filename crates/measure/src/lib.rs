//! Measurement harness — instruments before trust.
//!
//! Produces machine-readable claims with PASS / FAIL / BLOCKED / NOT_RUN / SKIP.
//! Never converts infrastructure failure into PASS.

pub mod bench;
pub mod claims;
pub mod expect;
pub mod suite;

pub use bench::{run_benches, BenchReport, BenchSample};
pub use claims::{ClaimRecord, ClaimStatus, Ledger};
pub use expect::{FixtureExpectation, default_catalog};
pub use suite::{run_fixture_suite, MeasureReport, SuiteOptions};
