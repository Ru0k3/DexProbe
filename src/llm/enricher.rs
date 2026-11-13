use std::io::Read;
use std::time::Duration;

use serde_json::json;

use crate::config;
use crate::core::logger;
use crate::models::finding::Finding;

pub fn enrich(mut findings: Vec<Finding>, skip_llm: bool) -> Vec<Finding> {
    if skip_llm {
        logger::info("LLM enrichment skipped (--skip-llm).");
        return findings;
    }

    let key = config::gemini_api_key();
    if key.is_empty() {
        logger::info("Gemini API key not configured; continuing in offline mode.");
        return findings;
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(config::REQUEST_DEADLINE_SECS))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            logger::warn(&format!("Gemini client unavailable: {error}"));
            return findings;
        }
    };

    logger::section("LLM ENRICHMENT", 54);
    for finding in &mut findings {
        match enrich_one(&client, &key, finding) {
            Ok((risk, attack, fix)) => {
                finding.llm_risk = Some(risk);
                finding.llm_attack = Some(attack);
                finding.llm_fix = Some(fix);
            }
            Err(error) => logger::warn(&format!("Gemini enrichment failed: {error}")),
        }
    }
    findings
}

fn enrich_one(
    client: &reqwest::blocking::Client,
    key: &str,
    finding: &Finding,
) -> anyhow::Result<(String, String, String)> {
    let endpoint = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent",
        config::GEMINI_MODEL
    );
    let body = json!({
        "contents": [{"parts": [{"text": crate::llm::prompts::build_prompt(finding)}]}],
        "generationConfig": {"temperature": 0.1}
    });
    let mut last_error = None;
    for attempt in 0..=config::GEMINI_MAX_RETRIES {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(
                config::GEMINI_RETRY_DELAY_SECS * attempt as u64,
            ));
        }
        let response = client
            .post(&endpoint)
            .header("x-goog-api-key", key)
            .json(&body)
            .send();
        match response {
            Ok(response) if response.status().is_success() => {
                if response
                    .content_length()
                    .is_some_and(|size| size > config::MAX_REQUEST_BYTES)
                {
                    anyhow::bail!("Gemini response exceeded configured size limit");
                }
                let mut bytes = Vec::new();
                response
                    .take(config::MAX_REQUEST_BYTES + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() as u64 > config::MAX_REQUEST_BYTES {
                    anyhow::bail!("Gemini response exceeded configured size limit");
                }
                let payload: serde_json::Value = serde_json::from_slice(&bytes)?;
                let text = payload["candidates"][0]["content"]["parts"][0]["text"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Gemini response did not contain text"))?;
                return parse_sections(text);
            }
            Ok(response) => {
                last_error = Some(anyhow::anyhow!("Gemini returned {}", response.status()));
            }
            Err(error) => last_error = Some(error.into()),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Gemini request failed")))
}

fn parse_sections(text: &str) -> anyhow::Result<(String, String, String)> {
    let risk = section(text, "RISK", "ATTACK")?;
    let attack = section(text, "ATTACK", "FIX")?;
    let fix = text
        .split_once("FIX:")
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Gemini response did not contain FIX section"))?;
    Ok((risk, attack, fix))
}

fn section(text: &str, start: &str, end: &str) -> anyhow::Result<String> {
    let marker = format!("{start}:");
    let value = text
        .split_once(&marker)
        .and_then(|(_, rest)| rest.split_once(&format!("{end}:")).map(|(value, _)| value))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("Gemini response did not contain {start} section"))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::parse_sections;

    #[test]
    fn parses_structured_sections() {
        let result = parse_sections("RISK: risk text\nATTACK: attack text\nFIX: fix text").unwrap();
        assert_eq!(result.0, "risk text");
        assert_eq!(result.1, "attack text");
        assert_eq!(result.2, "fix text");
    }

    #[test]
    fn rejects_unstructured_response() {
        assert!(parse_sections("not structured").is_err());
    }
}
