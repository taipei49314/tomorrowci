//! Horizon comparison — base vs head regression detection (deterministic).

use crate::domain::BreakageFrontier;
use serde::{Deserialize, Serialize};

/// How a head horizon relates to a base horizon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HorizonMovement {
    /// Both absent or same label.
    Unchanged,
    /// Head breaks later (or clears a prior horizon) — good for the project.
    Improved,
    /// Head breaks earlier or introduces a horizon — bad for the project.
    Regressed,
    /// Cannot compare honestly (missing labels, mixed grades, etc.).
    Incomparable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HorizonCompare {
    pub movement: HorizonMovement,
    pub base_observed: bool,
    pub head_observed: bool,
    pub base_label: Option<String>,
    pub head_label: Option<String>,
    pub base_order_key: Option<String>,
    pub head_order_key: Option<String>,
    pub explanation: String,
    /// True when movement == Regressed (policy gate helper).
    pub is_regression: bool,
}

/// Extract a sortable order key from a horizon label (best-effort).
/// Prefers first `major.minor` or `major.minor.patch` token; else the whole label.
pub fn order_key_from_label(label: &str) -> String {
    // Python 3.10, Node.js 20, Rust 1.85
    let re = regex::Regex::new(r"(\d+\.\d+(?:\.\d+)?|\b\d{1,2}\b)").ok();
    if let Some(re) = re {
        if let Some(caps) = re.captures(label) {
            let raw = caps.get(1).map(|m| m.as_str()).unwrap_or(label);
            // Normalize single majors (Node 20) to 20.0 for compare
            if !raw.contains('.') {
                return format!("{raw}.0");
            }
            return raw.to_string();
        }
    }
    label.to_string()
}

/// Compare two order keys. Returns Some(std::cmp::Ordering) when both parse as version-ish.
pub fn cmp_order_keys(a: &str, b: &str) -> std::cmp::Ordering {
    let pa = parse_ver_parts(a);
    let pb = parse_ver_parts(b);
    match (pa, pb) {
        (Some(x), Some(y)) => x.cmp(&y),
        _ => a.cmp(b),
    }
}

fn parse_ver_parts(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let patch = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// Compare base vs head frontiers.
///
/// Semantics: an **earlier** breakage horizon is a **regression** (compatibility
/// is worse). Clearing a horizon is an improvement.
pub fn compare_horizons(base: &BreakageFrontier, head: &BreakageFrontier) -> HorizonCompare {
    let base_label = base.horizon_label.clone();
    let head_label = head.horizon_label.clone();
    let base_key = base_label.as_deref().map(order_key_from_label);
    let head_key = head_label.as_deref().map(order_key_from_label);

    match (base.observed, head.observed) {
        (false, false) => HorizonCompare {
            movement: HorizonMovement::Unchanged,
            base_observed: false,
            head_observed: false,
            base_label,
            head_label,
            base_order_key: base_key,
            head_order_key: head_key,
            explanation: "No observed breakage horizon on base or head.".into(),
            is_regression: false,
        },
        (false, true) => HorizonCompare {
            movement: HorizonMovement::Regressed,
            base_observed: false,
            head_observed: true,
            base_label,
            head_label: head_label.clone(),
            base_order_key: base_key,
            head_order_key: head_key,
            explanation: format!(
                "Regression: head introduces horizon '{}' where base had none.",
                head_label.as_deref().unwrap_or("?")
            ),
            is_regression: true,
        },
        (true, false) => HorizonCompare {
            movement: HorizonMovement::Improved,
            base_observed: true,
            head_observed: false,
            base_label: base_label.clone(),
            head_label,
            base_order_key: base_key,
            head_order_key: head_key,
            explanation: format!(
                "Improvement: base horizon '{}' is cleared on head.",
                base_label.as_deref().unwrap_or("?")
            ),
            is_regression: false,
        },
        (true, true) => {
            let (bk, hk) = match (base_key.as_deref(), head_key.as_deref()) {
                (Some(a), Some(b)) => (a.to_string(), b.to_string()),
                _ => {
                    return HorizonCompare {
                        movement: HorizonMovement::Incomparable,
                        base_observed: true,
                        head_observed: true,
                        base_label,
                        head_label,
                        base_order_key: base_key,
                        head_order_key: head_key,
                        explanation: "Both observed horizons but labels lack comparable order keys."
                            .into(),
                        is_regression: false,
                    };
                }
            };
            match cmp_order_keys(&bk, &hk) {
                std::cmp::Ordering::Equal => HorizonCompare {
                    movement: HorizonMovement::Unchanged,
                    base_observed: true,
                    head_observed: true,
                    base_label,
                    head_label,
                    base_order_key: Some(bk),
                    head_order_key: Some(hk),
                    explanation: "Horizons match (same order key).".into(),
                    is_regression: false,
                },
                std::cmp::Ordering::Less => HorizonCompare {
                    // base key < head key → head breaks later → improved
                    movement: HorizonMovement::Improved,
                    base_observed: true,
                    head_observed: true,
                    base_label,
                    head_label,
                    base_order_key: Some(bk.clone()),
                    head_order_key: Some(hk.clone()),
                    explanation: format!("Improvement: horizon moved later ({bk} → {hk})."),
                    is_regression: false,
                },
                std::cmp::Ordering::Greater => HorizonCompare {
                    movement: HorizonMovement::Regressed,
                    base_observed: true,
                    head_observed: true,
                    base_label,
                    head_label,
                    base_order_key: Some(bk.clone()),
                    head_order_key: Some(hk.clone()),
                    explanation: format!("Regression: horizon moved earlier ({bk} → {hk})."),
                    is_regression: true,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::BreakageFrontier;

    fn fr(observed: bool, label: Option<&str>) -> BreakageFrontier {
        BreakageFrontier {
            observed,
            horizon_label: label.map(|s| s.into()),
            scenario_id: None,
            axis: None,
            from_label: None,
            to_label: None,
            failure_signature: None,
            evidence_grade: None,
            replay_command: None,
            explanation: String::new(),
        }
    }

    #[test]
    fn new_horizon_is_regression() {
        let c = compare_horizons(&fr(false, None), &fr(true, Some("Python 3.10")));
        assert!(c.is_regression);
        assert_eq!(c.movement, HorizonMovement::Regressed);
    }

    #[test]
    fn earlier_horizon_is_regression() {
        let c = compare_horizons(
            &fr(true, Some("Python 3.12 + locked")),
            &fr(true, Some("Python 3.10 + locked")),
        );
        assert!(c.is_regression);
        assert_eq!(c.movement, HorizonMovement::Regressed);
    }

    #[test]
    fn later_horizon_is_improvement() {
        let c = compare_horizons(
            &fr(true, Some("Python 3.10")),
            &fr(true, Some("Python 3.12")),
        );
        assert!(!c.is_regression);
        assert_eq!(c.movement, HorizonMovement::Improved);
    }

    #[test]
    fn cleared_horizon_is_improvement() {
        let c = compare_horizons(&fr(true, Some("Python 3.10")), &fr(false, None));
        assert_eq!(c.movement, HorizonMovement::Improved);
    }

    #[test]
    fn order_key_python() {
        assert_eq!(order_key_from_label("Python 3.10 + locked"), "3.10");
    }
}
