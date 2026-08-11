//! TomorrowCI core: typed domain model, configuration, planner, and verdicts.
//!
//! Verdict classification is deterministic and never depends on an LLM.

pub mod backtest;
pub mod compare;
pub mod config;
pub mod ddmin;
pub mod domain;
pub mod error;
pub mod patch;
pub mod planner;
pub mod policy;
pub mod redaction;
pub mod replay_v2;
pub mod safety;
pub mod signature;
pub mod verdict;
pub mod weather;

pub use compare::{compare_horizons, order_key_from_label, HorizonCompare, HorizonMovement};
pub use config::{Config, ConfigError};
pub use domain::*;
pub use error::CoreError;
pub use indexmap::IndexMap;
pub use patch::*;
pub use planner::{PlanDecision, Planner, PlannerOutput};
pub use policy::{evaluate_policy, FailIf, PolicyConfig, PolicyDecision, PolicyReport};
pub use replay_v2::*;
pub use verdict::{authorize_frontier, classify_scenario, FrontierAuthorization};
pub use weather::*;
