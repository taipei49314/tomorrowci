//! Measurement instruments (量測器) — not telemetry, no network export by default.
//!
//! Records local scan metrics and claim-to-evidence rows so trust claims stay falsifiable.

mod claims;
mod scan;
mod trust;

pub use claims::*;
pub use scan::*;
pub use trust::*;
