//! TomorrowCI core: typed domain model, configuration, planner, and verdicts.
//!
//! Verdict classification is deterministic and never depends on an LLM.

pub mod config;
pub mod ddmin;
pub mod domain;
pub mod error;
pub mod planner;
pub mod redaction;
pub mod safety;
pub mod signature;
pub mod verdict;

pub use config::{Config, ConfigError};
pub use domain::*;
pub use error::CoreError;
pub use indexmap::IndexMap;
pub use planner::{PlanDecision, Planner, PlannerOutput};
pub use verdict::{authorize_frontier, classify_scenario, FrontierAuthorization};
