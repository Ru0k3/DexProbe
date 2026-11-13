/// core/scorer.rs — Severity Scoring & Sorting.
///
/// Mirror of `core/scorer.py`.
///
/// Public API
/// ----------
///   score_findings(findings) -> Vec<Finding>  (sorted descending by score)
///   severity_label(score) -> &'static str     CRITICAL / HIGH / MEDIUM / LOW
///   severity_score(label) -> f64              inverse of the above
use crate::config::SEVERITY_CRITICAL;
use crate::models::finding::Finding;

/// Apply severity labels where missing, then sort by score descending.
///
/// Pipelines are expected to set `finding.score` themselves; this function
/// normalises the `.severity` label to match and returns a clean sorted list.
pub fn score_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut findings = findings;
    for f in &mut findings {
        f.severity = severity_label(f.score).to_string();
    }
    findings.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.pipeline.cmp(&b.pipeline))
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.location.cmp(&b.location))
            .then_with(|| a.evidence.cmp(&b.evidence))
    });
    findings
}

/// Map a numeric score (0--10) to a severity label.
///
/// Thresholds: CRITICAL >= 9.0, HIGH >= 7.0, MEDIUM >= 4.0, else LOW.
pub fn severity_label(score: f64) -> &'static str {
    if score >= 9.0 {
        SEVERITY_CRITICAL
    } else if score >= 7.0 {
        crate::config::SEVERITY_HIGH
    } else if score >= 4.0 {
        crate::config::SEVERITY_MEDIUM
    } else {
        crate::config::SEVERITY_LOW
    }
}

/// Inverse of `severity_label`: numeric score implied by a severity label.
///
/// Useful for pipelines to assign an initial score from a discovered severity.
pub fn severity_score(label: &str) -> f64 {
    match label {
        SEVERITY_CRITICAL => 9.0,
        crate::config::SEVERITY_HIGH => 7.0,
        crate::config::SEVERITY_MEDIUM => 4.0,
        crate::config::SEVERITY_LOW => 1.0,
        crate::config::SEVERITY_INFO => 0.0,
        _ => 0.0,
    }
}

/// Severity labels in descending order.
pub const SEVERITY_ORDER: &[&str] = &[
    SEVERITY_CRITICAL,
    crate::config::SEVERITY_HIGH,
    crate::config::SEVERITY_MEDIUM,
    crate::config::SEVERITY_LOW,
];
