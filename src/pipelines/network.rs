use crate::core::UnpackedApk;
use crate::models::finding::Finding;

pub const PIPELINE_NAME: &str = "network";

pub fn run(unpacked: &UnpackedApk) -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in unpacked.res_files.iter().chain(unpacked.dex_files.iter()) {
        if let Ok(bytes) = std::fs::read(path) {
            scan_text(
                &mut findings,
                &path.display().to_string(),
                &String::from_utf8_lossy(&bytes),
            );
        }
    }
    findings
}

fn scan_text(findings: &mut Vec<Finding>, location: &str, text: &str) {
    for token in text
        .split_whitespace()
        .map(|token| token.trim_matches(|c: char| c.is_ascii_punctuation()))
        .filter(|token| token.starts_with("http://") || token.starts_with("https://"))
    {
        let lower = token.to_ascii_lowercase();
        if lower.starts_with("http://") {
            findings.push(network_finding(
                "Cleartext HTTP endpoint",
                "The APK contains a non-HTTPS endpoint.",
                token,
                location,
                7.0,
            ));
        }
        if crate::config::SUSPICIOUS_TLDS
            .iter()
            .any(|tld| lower.contains(tld))
        {
            findings.push(network_finding(
                "Suspicious domain suffix detected",
                "The APK contains a domain using a high-risk TLD.",
                token,
                location,
                6.0,
            ));
        }
        if lower.contains(":8080") || lower.contains(":8443") || lower.contains(":8888") {
            findings.push(network_finding(
                "Non-standard network port detected",
                "The APK contains a URL using a non-standard port.",
                token,
                location,
                4.0,
            ));
        }
    }
}

fn network_finding(
    title: &str,
    detail: &str,
    evidence: &str,
    location: &str,
    score: f64,
) -> Finding {
    let mut finding = Finding::new(PIPELINE_NAME, title, detail);
    finding.score = score;
    finding.location = location.into();
    finding.evidence = evidence.into();
    finding.redacted_evidence = "[REDACTED URL]".into();
    finding.evidence_source = location.into();
    finding
}

#[cfg(test)]
mod tests {
    use super::scan_text;

    #[test]
    fn classifies_http_tld_and_port() {
        let mut findings = Vec::new();
        scan_text(
            &mut findings,
            "resources.arsc",
            "http://example.xyz:8080/api",
        );
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn ignores_non_url_text() {
        let mut findings = Vec::new();
        scan_text(&mut findings, "classes.dex", "example.xyz:8080");
        assert!(findings.is_empty());
    }

    #[test]
    fn never_exposes_url_credentials_or_query_values_as_evidence() {
        let mut findings = Vec::new();
        scan_text(
            &mut findings,
            "assets/config.txt",
            "http://user:password@example.com/path?token=secret",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].redacted_evidence, "[REDACTED URL]");
        assert!(
            !serde_json::to_string(&findings[0])
                .unwrap()
                .contains("password")
        );
        assert!(
            !serde_json::to_string(&findings[0])
                .unwrap()
                .contains("secret")
        );
    }
}
