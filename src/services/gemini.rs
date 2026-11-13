use crate::models::finding::Finding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrichment {
    pub risk: String,
    pub attack: String,
    pub fix: String,
    pub status: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("request timed out")]
    Timeout,
    #[error("service rate limited")]
    RateLimited,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("invalid service response: {0}")]
    InvalidResponse(String),
    #[error("service unavailable: {0}")]
    Unavailable(String),
}

pub struct GeminiClient {
    client: reqwest::blocking::Client,
    endpoint: String,
    api_key: String,
}

impl GeminiClient {
    pub fn new(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self, ServiceError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(
                crate::config::REQUEST_DEADLINE_SECS,
            ))
            .build()
            .map_err(|error| ServiceError::Transport(error.to_string()))?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
            api_key: api_key.into(),
        })
    }

    pub fn enrich(&self, finding: &Finding) -> Result<Enrichment, ServiceError> {
        let response = self
            .client
            .post(&self.endpoint)
            .header("x-goog-api-key", &self.api_key)
            .json(&serde_json::json!({
                "contents": [{"parts": [{"text": crate::llm::prompts::build_prompt(finding)}]}]
            }))
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    ServiceError::Timeout
                } else {
                    ServiceError::Transport(error.to_string())
                }
            })?;
        if response.status().as_u16() == 429 {
            return Err(ServiceError::RateLimited);
        }
        if !response.status().is_success() {
            return Err(ServiceError::Unavailable(response.status().to_string()));
        }
        let payload: serde_json::Value = response
            .json()
            .map_err(|error| ServiceError::InvalidResponse(error.to_string()))?;
        let text = payload["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .ok_or_else(|| ServiceError::InvalidResponse("missing generated text".into()))?;
        parse_enrichment(text)
    }
}

fn parse_enrichment(text: &str) -> Result<Enrichment, ServiceError> {
    let risk = section(text, "RISK", "ATTACK")?;
    let attack = section(text, "ATTACK", "FIX")?;
    let fix = text
        .split_once("FIX:")
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ServiceError::InvalidResponse("missing FIX section".into()))?;
    Ok(Enrichment {
        risk,
        attack,
        fix: fix.into(),
        status: "complete".into(),
    })
}

fn section(text: &str, start: &str, end: &str) -> Result<String, ServiceError> {
    text.split_once(&format!("{start}:"))
        .and_then(|(_, rest)| rest.split_once(&format!("{end}:")))
        .map(|(value, _)| value.trim())
        .filter(|value| !value.is_empty())
        .map(String::from)
        .ok_or_else(|| ServiceError::InvalidResponse(format!("missing {start} section")))
}

#[cfg(test)]
mod tests {
    use super::parse_enrichment;

    #[test]
    fn parses_structured_enrichment() {
        let result = parse_enrichment("RISK: risk\nATTACK: attack\nFIX: fix").expect("parse");
        assert_eq!(result.status, "complete");
        assert_eq!(result.fix, "fix");
    }

    #[test]
    fn rejects_unstructured_enrichment() {
        assert!(parse_enrichment("unstructured").is_err());
    }
}
