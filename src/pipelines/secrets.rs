use crate::core::UnpackedApk;
use crate::models::finding::Finding;

pub const PIPELINE_NAME: &str = "secrets";

pub fn run(unpacked: &UnpackedApk) -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in &unpacked.res_files {
        if let Ok(bytes) = std::fs::read(path) {
            scan_text(
                &mut findings,
                &path.display().to_string(),
                &String::from_utf8_lossy(&bytes),
            );
        }
    }
    for path in &unpacked.dex_files {
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
    for (prefix, title, score) in [
        ("AKIA", "AWS access key detected", 9.0),
        ("AIza", "Google API key detected", 8.0),
        ("ghp_", "GitHub token detected", 9.0),
        ("sk_live_", "Stripe secret key detected", 9.0),
        (
            "-----BEGIN RSA PRIVATE KEY-----",
            "Private key detected",
            10.0,
        ),
        ("Bearer ", "Bearer token detected", 8.0),
    ] {
        if let Some(index) = text.find(prefix) {
            let evidence = &text[index..text.len().min(index + 16)];
            let mut finding = Finding::new(
                PIPELINE_NAME,
                title,
                "A credential-like value was found in APK content.",
            );
            finding.score = score;
            finding.location = location.to_string();
            finding.evidence = format!("{}…", &evidence[..evidence.len().min(8)]);
            finding.redacted_evidence = "[REDACTED]".into();
            finding.evidence_source = location.into();
            finding.tags.push("heuristic".into());
            findings.push(finding);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::scan_text;

    #[test]
    fn detects_and_redacts_credential_like_values() {
        let mut findings = Vec::new();
        scan_text(
            &mut findings,
            "classes.dex",
            "prefix AKIA1234567890SECRET suffix",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].redacted_evidence, "[REDACTED]");
        assert!(
            !serde_json::to_string(&findings[0])
                .expect("serialize finding")
                .contains("AKIA")
        );
    }

    #[test]
    fn ignores_unrelated_text() {
        let mut findings = Vec::new();
        scan_text(&mut findings, "classes.dex", "ordinary application text");
        assert!(findings.is_empty());
    }
}
