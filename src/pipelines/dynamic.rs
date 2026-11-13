use crate::core::UnpackedApk;
use crate::models::finding::Finding;

pub const PIPELINE_NAME: &str = "dynamic";

pub fn run(unpacked: &UnpackedApk) -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in &unpacked.dex_files {
        let Ok(dex) = crate::core::dex::parse_file(path) else {
            continue;
        };
        for class in dex.class_defs {
            for method in class
                .direct_methods
                .iter()
                .chain(class.virtual_methods.iter())
            {
                let Some(code) = &method.code else {
                    continue;
                };
                for instruction in &code.instructions {
                    let Some(reference) = instruction.resolved_value.as_deref() else {
                        continue;
                    };
                    let location = format!("{}::{}", class.name, method.name);
                    for (needle, title, score) in [
                        ("DexClassLoader", "Dynamic DEX loading detected", 7.0),
                        ("PathClassLoader", "Dynamic class loading detected", 6.0),
                        ("loadClass", "Reflective class loading detected", 6.0),
                        (
                            "Runtime;->exec",
                            "Runtime command execution API referenced",
                            8.0,
                        ),
                        ("java.lang.reflect", "Reflection API referenced", 5.0),
                    ] {
                        if reference.contains(needle) {
                            let mut finding = Finding::new(
                                PIPELINE_NAME,
                                title,
                                format!("Parsed DEX instruction references {reference}."),
                            );
                            finding.score = score;
                            finding.location = format!("{}:{}", path.display(), location);
                            finding.evidence = reference.into();
                            finding.redacted_evidence = reference.into();
                            finding.evidence_source = "parsed DEX instruction".into();
                            finding.precision = crate::models::finding::EvidencePrecision::Exact;
                            finding.confidence = crate::models::finding::Confidence::Confirmed;
                            findings.push(finding);
                        }
                    }
                }
            }
        }
    }
    findings
}

fn scan_text(findings: &mut Vec<Finding>, location: &str, text: &str) {
    for (needle, title, score) in [
        ("DexClassLoader", "Dynamic DEX loading detected", 7.0),
        ("PathClassLoader", "Dynamic class loading detected", 6.0),
        ("loadClass", "Reflective class loading detected", 6.0),
        (
            "Runtime;->exec",
            "Runtime command execution API referenced",
            8.0,
        ),
        ("java.lang.reflect", "Reflection API referenced", 5.0),
    ] {
        if text.contains(needle) {
            let mut finding = Finding::new(
                PIPELINE_NAME,
                title,
                format!(
                    "Bytecode references {needle}; intent and loaded content require manual review."
                ),
            );
            finding.score = score;
            finding.location = location.into();
            finding.evidence = needle.into();
            finding.redacted_evidence = needle.into();
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
    fn detects_dynamic_loading_references() {
        let mut findings = Vec::new();
        scan_text(&mut findings, "classes.dex", "DexClassLoader");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].tags.iter().any(|tag| tag == "heuristic"));
    }
}
