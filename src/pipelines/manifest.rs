use crate::core::UnpackedApk;
use crate::models::finding::{Confidence, EvidencePrecision, Finding};

pub const PIPELINE_NAME: &str = "manifest";

pub fn run(unpacked: &UnpackedApk) -> Vec<Finding> {
    let Some(manifest) = &unpacked.decoded_manifest else {
        return Vec::new();
    };
    analyze(manifest)
}

fn analyze(manifest: &crate::core::unpacker::DecodedManifest) -> Vec<Finding> {
    let mut findings = Vec::new();
    if manifest.debuggable == Some(true) {
        findings.push(manifest_finding(
            "Debuggable application enabled",
            "The decoded manifest enables android:debuggable.",
            "debuggable=true",
            7.0,
            Confidence::Confirmed,
        ));
    }
    if manifest.allow_backup == Some(true) {
        findings.push(manifest_finding(
            "Application backup is enabled",
            "The decoded manifest enables application backup.",
            "allowBackup=true",
            5.0,
            Confidence::Probable,
        ));
    }
    if manifest.uses_cleartext_traffic == Some(true) {
        findings.push(manifest_finding(
            "Cleartext network traffic is enabled",
            "The decoded manifest permits cleartext network traffic.",
            "usesCleartextTraffic=true",
            7.0,
            Confidence::Confirmed,
        ));
    }
    if manifest.network_security_config.is_none() {
        findings.push(manifest_finding(
            "Network security configuration is missing",
            "No network security configuration is declared; review platform defaults and endpoint policy.",
            "networkSecurityConfig=missing",
            3.0,
            Confidence::Heuristic,
        ));
    }
    for permission in &manifest.permissions {
        if crate::config::HIGH_RISK_PERMISSIONS.contains(&permission.as_str()) {
            findings.push(manifest_finding(
                "High-risk permission declared",
                "The application requests a permission requiring explicit product justification.",
                permission,
                4.0,
                Confidence::Confirmed,
            ));
        }
    }
    for component in manifest
        .activities
        .iter()
        .chain(manifest.services.iter())
        .chain(manifest.receivers.iter())
        .chain(manifest.providers.iter())
    {
        if component.exported == Some(true) && component.permission.is_none() {
            findings.push(manifest_finding(
                "Exported component lacks permission protection",
                "An exported component has no declared permission protection; validate its intent and data boundaries.",
                &component.name,
                7.0,
                Confidence::Probable,
            ));
        }
    }
    findings
}

fn manifest_finding(
    title: &str,
    detail: &str,
    evidence: &str,
    score: f64,
    confidence: Confidence,
) -> Finding {
    let mut finding = Finding::new(PIPELINE_NAME, title, detail);
    finding.score = score;
    finding.location = "AndroidManifest.xml".into();
    finding.evidence = evidence.into();
    finding.redacted_evidence = evidence.into();
    finding.evidence_source = "decoded AndroidManifest.xml".into();
    finding.confidence = confidence;
    finding.precision = EvidencePrecision::Exact;
    finding
}

#[cfg(test)]
mod tests {
    use super::analyze;
    use crate::core::unpacker::{DecodedManifest, ManifestComponent};

    #[test]
    fn reports_decoded_manifest_risks() {
        let manifest = DecodedManifest {
            debuggable: Some(true),
            allow_backup: Some(true),
            uses_cleartext_traffic: Some(true),
            permissions: vec!["android.permission.CAMERA".into()],
            activities: vec![ManifestComponent {
                name: "com.example.MainActivity".into(),
                exported: Some(true),
                permission: None,
            }],
            ..DecodedManifest::default()
        };
        let findings = analyze(&manifest);
        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("Debuggable"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("Exported component"))
        );
    }
}
