pub mod enricher;
/// llm/ — Gemini API integration (LLM enrichment layer).
///
/// Mirror of `llm/`. Enriches findings with risk explanations, attack
/// scenarios and fix recommendations via Gemini.
///
/// Public API
/// ----------
///   enrich(findings, skip_llm) -> Vec<Finding>
///   build_prompt(finding) -> String
pub mod prompts;
