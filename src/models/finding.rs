/// models/finding.rs — Core Finding data model.
///
/// Mirror of `models/findings.py`. Every pipeline returns `Vec<Finding>`.
/// The orchestrator aggregates, scores and hands findings to the report
/// generator. Severity labels are normalised via `core::scorer`.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Confidence {
    Confirmed,
    Probable,
    Heuristic,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidencePrecision {
    Exact,
    File,
    Heuristic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Reachability {
    Reachable,
    PresentNotReachable,
    Unverified,
    NotApplicable,
}

/// All supported severity labels.
pub const SEVERITY_LABELS: &[&str] = &["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/// A single security finding from any pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Finding {
    pub schema_version: u32,
    /// Name of the pipeline that produced this finding
    /// (e.g. "manifest", "secrets", "network", "dependencies", "dynamic").
    pub pipeline: String,
    /// Short one-line summary (<= 80 chars).
    pub title: String,
    /// Longer description of what was found and where.
    pub detail: String,
    /// One of CRITICAL / HIGH / MEDIUM / LOW / INFO.
    pub severity: String,
    /// Raw numeric score 0--10 (used for sorting).
    pub score: f64,
    /// File path + line reference inside the APK or temp tree.
    pub location: String,
    /// The raw value that triggered the finding
    /// (e.g. partial key, URL, class name).
    #[serde(skip_serializing, default)]
    pub evidence: String,
    /// Free-form labels for filtering.
    pub tags: Vec<String>,
    pub confidence: Confidence,
    pub precision: EvidencePrecision,
    pub evidence_source: String,
    pub redacted_evidence: String,
    pub cve_ids: Vec<String>,
    pub reachability: Reachability,

    // Populated by LLM layer (Phase 9)
    pub llm_risk: Option<String>,
    pub llm_attack: Option<String>,
    pub llm_fix: Option<String>,
}

impl Finding {
    /// Severity inferred from the numeric score (0--10).
    /// Mirrors `core/scorer.severity_label()`.
    pub fn infer_severity(score: f64) -> &'static str {
        if score >= 9.0 {
            "CRITICAL"
        } else if score >= 7.0 {
            "HIGH"
        } else if score >= 4.0 {
            "MEDIUM"
        } else {
            "LOW"
        }
    }

    /// Create a new unsevered finding; severity/score are normalised later.
    pub fn new(
        pipeline: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            pipeline: pipeline.into(),
            title: title.into(),
            detail: detail.into(),
            severity: "LOW".to_string(),
            score: 0.0,
            location: String::new(),
            evidence: String::new(),
            tags: Vec::new(),
            confidence: Confidence::Heuristic,
            precision: EvidencePrecision::File,
            evidence_source: String::new(),
            redacted_evidence: String::new(),
            cve_ids: Vec::new(),
            reachability: Reachability::NotApplicable,
            llm_risk: None,
            llm_attack: None,
            llm_fix: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Finding;

    #[test]
    fn serialized_findings_reload_without_raw_evidence() {
        let mut finding = Finding::new("secrets", "Key", "detail");
        finding.evidence = "private-value".into();
        finding.redacted_evidence = "[REDACTED]".into();
        let json = serde_json::to_vec(&finding).expect("serialize finding");
        assert!(!String::from_utf8_lossy(&json).contains("private-value"));
        let restored: Finding = serde_json::from_slice(&json).expect("deserialize finding");
        assert!(restored.evidence.is_empty());
        assert_eq!(restored.redacted_evidence, "[REDACTED]");
    }
}
