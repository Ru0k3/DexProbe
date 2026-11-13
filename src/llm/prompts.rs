/// llm/prompts.rs — Prompt templates for Gemini enrichment.
///
/// Mirror of `llm/prompts.py`. One `build_prompt()` function per pipeline
/// type. Activated in Phase 9.
use crate::models::finding::Finding;

/// Build a structured Gemini prompt for a single finding.
pub fn build_prompt(finding: &Finding) -> String {
    format!(
        "Pipeline: {pipeline}\nFinding: {title}\nDetail: {detail}\nEvidence: {evidence}\n\n\
         Respond with three sections:\n1. RISK: Plain-English explanation of the security risk.\n2. ATTACK: Step-by-step attack scenario.\n3. FIX: Exact code or config change needed to fix it.",
        pipeline = finding.pipeline,
        title = finding.title,
        detail = finding.detail,
        evidence = if finding.redacted_evidence.is_empty() {
            "[REDACTED]"
        } else {
            &finding.redacted_evidence
        }
    )
}
