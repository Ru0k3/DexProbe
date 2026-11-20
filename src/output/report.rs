use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::core::logger;
use crate::models::finding::Finding;
use std::collections::BTreeMap;

pub const REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct Meta {
    pub tool: String,
    pub version: String,
    pub apk_path: String,
    pub scan_time: String,
    pub skip_llm: bool,
    pub pipeline: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report<'a> {
    pub schema_version: u32,
    pub meta: &'a Meta,
    pub summary: ReportSummary,
    pub pipelines: Vec<PipelineSummary>,
    pub findings: &'a [Finding],
    pub policy: PolicyResult,
}

#[derive(Debug, Serialize)]
pub struct ReportSummary {
    pub total: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub most_critical_pipeline: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PipelineSummary {
    pub pipeline: String,
    pub findings: usize,
    pub highest_severity: String,
}

#[derive(Debug, Serialize)]
pub struct PolicyResult {
    pub fail_policy: String,
    pub threshold: Option<String>,
    pub exceeded: bool,
}

pub fn render_terminal(findings: &[Finding], _meta: &Meta) {
    logger::section("SCAN REPORT", 54);
    if findings.is_empty() {
        println!("No findings.");
        return;
    }
    for finding in findings {
        println!(
            "[{}] {} ({:.1})",
            finding.severity, finding.title, finding.score
        );
        if !finding.location.is_empty() {
            println!("  Location: {}", finding.location);
        }
        let evidence = redacted_evidence(finding);
        if !evidence.is_empty() {
            println!("  Evidence: {evidence}");
        }
    }
}

pub fn export_json(
    findings: &[Finding],
    meta: &Meta,
    output_path: &Path,
    fail_policy: &str,
    threshold: Option<String>,
    exceeded: bool,
) -> anyhow::Result<()> {
    let sanitized = findings
        .iter()
        .cloned()
        .map(|mut finding| {
            if finding.redacted_evidence.is_empty() {
                finding.redacted_evidence = redact(&finding.evidence);
            }
            finding
        })
        .collect::<Vec<_>>();
    let report = Report {
        schema_version: REPORT_SCHEMA_VERSION,
        meta,
        summary: summary(&sanitized),
        pipelines: pipeline_summaries(&sanitized),
        findings: &sanitized,
        policy: PolicyResult {
            fail_policy: fail_policy.into(),
            threshold,
            exceeded,
        },
    };
    let json = serde_json::to_string_pretty(&report)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temporary = output_path.with_extension(format!("json.{nonce}.tmp"));
    std::fs::write(&temporary, json)?;
    std::fs::rename(temporary, output_path)?;
    logger::ok(&format!("JSON report -> {}", output_path.display()));
    Ok(())
}

pub fn export_sarif(findings: &[Finding], meta: &Meta, output_path: &Path) -> anyhow::Result<()> {
    let rules = findings
        .iter()
        .map(|finding| finding.pipeline.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|id| {
            serde_json::json!({
                "id": id,
                "shortDescription": { "text": format!("{id} analysis finding") }
            })
        })
        .collect::<Vec<_>>();
    let results = findings
        .iter()
        .map(|finding| {
            let evidence = redacted_evidence(finding);
            let message = if evidence.is_empty() {
                finding.detail.clone()
            } else {
                format!("{} Evidence: {evidence}", finding.detail)
            };
            let mut result = serde_json::json!({
                "ruleId": finding.pipeline,
                "level": match finding.severity.as_str() {
                    "CRITICAL" | "HIGH" => "error",
                    "MEDIUM" => "warning",
                    _ => "note",
                },
                "message": { "text": message },
                "properties": {
                    "severity": finding.severity,
                    "score": finding.score,
                    "confidence": finding.confidence,
                    "reachability": finding.reachability,
                    "tags": finding.tags,
                    "cve_ids": finding.cve_ids,
                    "apk_location": apk_entry_path(&finding.location),
                },
            });
            if !finding.location.is_empty() {
                result["locations"] = serde_json::json!([{
                    "physicalLocation": {
                        "artifactLocation": { "uri": meta.apk_path }
                    }
                }]);
            }
            result
        })
        .collect::<Vec<_>>();
    let report = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": meta.tool, "version": meta.version, "rules": rules } },
            "results": results,
        }],
    });
    write_report(output_path, &serde_json::to_vec_pretty(&report)?)?;
    logger::ok(&format!("SARIF report -> {}", output_path.display()));
    Ok(())
}

fn apk_entry_path(location: &str) -> &str {
    ["/resources/", "/dex/", "/manifest/"]
        .iter()
        .find_map(|prefix| location.rsplit_once(prefix).map(|(_, entry)| entry))
        .unwrap_or(location)
}

fn write_report(output_path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temporary = output_path.with_extension(format!("report.{nonce}.tmp"));
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(temporary, output_path)?;
    Ok(())
}

fn redacted_evidence(finding: &Finding) -> String {
    if !finding.redacted_evidence.is_empty() {
        finding.redacted_evidence.clone()
    } else {
        redact(&finding.evidence)
    }
}

fn redact(value: &str) -> String {
    if value.chars().count() <= 8 {
        return "[REDACTED]".to_string();
    }
    let first = value.chars().take(4).collect::<String>();
    let last = value
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{first}…{last}")
}

fn summary(findings: &[Finding]) -> ReportSummary {
    let mut by_severity = BTreeMap::new();
    let mut pipeline_scores = BTreeMap::<String, f64>::new();
    for finding in findings {
        *by_severity.entry(finding.severity.clone()).or_insert(0) += 1;
        pipeline_scores
            .entry(finding.pipeline.clone())
            .and_modify(|score| *score = score.max(finding.score))
            .or_insert(finding.score);
    }
    let most_critical_pipeline = pipeline_scores
        .into_iter()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(pipeline, _)| pipeline);
    ReportSummary {
        total: findings.len(),
        by_severity,
        most_critical_pipeline,
    }
}

fn pipeline_summaries(findings: &[Finding]) -> Vec<PipelineSummary> {
    let mut summaries = BTreeMap::<String, (usize, f64, String)>::new();
    for finding in findings {
        let entry = summaries.entry(finding.pipeline.clone()).or_insert((
            0,
            finding.score,
            finding.severity.clone(),
        ));
        entry.0 += 1;
        if finding.score > entry.1 {
            entry.1 = finding.score;
            entry.2 = finding.severity.clone();
        }
    }
    summaries
        .into_iter()
        .map(
            |(pipeline, (findings, _, highest_severity))| PipelineSummary {
                pipeline,
                findings,
                highest_severity,
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{Meta, export_sarif, redacted_evidence, summary};
    use crate::models::finding::Finding;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn summary_counts_findings_and_pipeline_severity() {
        let mut finding = Finding::new("network", "HTTP", "detail");
        finding.score = 7.0;
        finding.severity = "HIGH".into();
        let report_summary = summary(&[finding]);
        assert_eq!(report_summary.total, 1);
        assert_eq!(report_summary.by_severity.get("HIGH").copied(), Some(1));
        assert_eq!(
            report_summary.most_critical_pipeline.as_deref(),
            Some("network")
        );
    }

    #[test]
    fn terminal_evidence_is_redacted_by_default() {
        let mut finding = Finding::new("secrets", "Key", "detail");
        finding.evidence = "AKIA1234567890".into();
        assert_eq!(redacted_evidence(&finding), "AKIA…7890");
    }

    #[test]
    fn redacts_unicode_evidence_without_panicking() {
        let mut finding = Finding::new("network", "URL", "detail");
        finding.evidence = "éééésecretéééé".into();
        assert_eq!(redacted_evidence(&finding), "éééé…éééé");
    }

    #[test]
    fn sarif_is_versioned_and_does_not_export_raw_evidence() {
        let path = std::env::temp_dir().join(format!(
            "dexprobe-sarif-test-{}-{}.sarif",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut finding = Finding::new("secrets", "Credential", "Possible credential");
        finding.evidence = "raw-secret-value".into();
        finding.location = "classes.dex".into();
        let meta = Meta {
            tool: "dexprobe".into(),
            version: "0.1.0".into(),
            apk_path: "app.apk".into(),
            scan_time: "2026-01-01T00:00:00Z".into(),
            skip_llm: true,
            pipeline: None,
        };

        export_sarif(&[finding], &meta, &path).expect("write SARIF");
        let bytes = std::fs::read(&path).expect("read SARIF");
        let _ = std::fs::remove_file(path);
        let text = String::from_utf8(bytes).expect("SARIF UTF-8");
        let report: serde_json::Value = serde_json::from_str(&text).expect("SARIF JSON");
        assert_eq!(report["version"], "2.1.0");
        assert_eq!(
            report["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "secrets"
        );
        assert_eq!(report["runs"][0]["results"][0]["ruleId"], "secrets");
        assert_eq!(
            report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "app.apk"
        );
        assert_eq!(
            report["runs"][0]["results"][0]["properties"]["apk_location"],
            "classes.dex"
        );
        assert!(
            report["runs"][0]["results"][0]["message"]["text"]
                .as_str()
                .unwrap()
                .contains("Evidence:")
        );
        assert!(!text.contains("raw-secret-value"));
    }
}
