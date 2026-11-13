use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyIdentity {
    pub library: String,
    pub package_prefix: String,
    pub version: Option<String>,
    pub evidence_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheKey {
    pub library: String,
    pub package_prefix: String,
    pub version: String,
    pub scanner_schema_version: u32,
    pub parser_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveRecord {
    pub id: String,
    pub description: String,
    pub cvss: Option<f64>,
    pub source_url: String,
    pub applicability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub fetched_at: u64,
    pub stale: bool,
    pub records: Vec<CveRecord>,
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

pub struct NvdClient {
    client: reqwest::blocking::Client,
    endpoint: String,
}

impl NvdClient {
    pub fn new(endpoint: impl Into<String>) -> Result<Self, ServiceError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(crate::config::REQUEST_DEADLINE_SECS))
            .build()
            .map_err(|error| ServiceError::Transport(error.to_string()))?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
        })
    }

    pub fn lookup(&self, identity: &DependencyIdentity) -> Result<Vec<CveRecord>, ServiceError> {
        let response = self
            .client
            .get(&self.endpoint)
            .query(&[("keywordSearch", identity.library.as_str())])
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
        if response
            .content_length()
            .is_some_and(|size| size > crate::config::MAX_REQUEST_BYTES)
        {
            return Err(ServiceError::InvalidResponse("response too large".into()));
        }
        let mut bytes = Vec::new();
        response
            .take(crate::config::MAX_REQUEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| ServiceError::Transport(error.to_string()))?;
        if bytes.len() as u64 > crate::config::MAX_REQUEST_BYTES {
            return Err(ServiceError::InvalidResponse("response too large".into()));
        }
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| ServiceError::InvalidResponse(error.to_string()))?;
        let mut records = Vec::new();
        for item in payload["vulnerabilities"].as_array().into_iter().flatten() {
            let cve = &item["cve"];
            let Some(id) = cve["id"].as_str() else {
                continue;
            };
            let description = cve["descriptions"]
                .as_array()
                .and_then(|values| values.first())
                .and_then(|value| value["value"].as_str())
                .unwrap_or_default()
                .to_string();
            let cvss = cve["metrics"]["cvssMetricV31"]
                .as_array()
                .and_then(|values| values.first())
                .and_then(|value| value["cvssData"]["baseScore"].as_f64());
            records.push(CveRecord {
                id: id.into(),
                description,
                cvss,
                source_url: format!("https://nvd.nist.gov/vuln/detail/{id}"),
                applicability: identity.version.clone().unwrap_or_else(|| "unknown".into()),
            });
        }
        Ok(records)
    }
}

#[derive(Debug)]
pub struct CveCache {
    path: PathBuf,
    entries: BTreeMap<String, CacheEntry>,
}

impl CveCache {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let entries = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self { path, entries }
    }

    pub fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        self.entries.get(&cache_key(key)).cloned()
    }

    pub fn put(&mut self, key: &CacheKey, entry: CacheEntry) {
        self.entries.insert(cache_key(key), entry);
    }

    pub fn flush(&self) -> Result<(), ServiceError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| ServiceError::Transport(error.to_string()))?;
        }
        let lock = self.path.with_extension("lock");
        let lock_file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                return Err(ServiceError::Unavailable("cache is locked".into()));
            }
            Err(error) => return Err(ServiceError::Transport(error.to_string())),
        };
        let temp = self.path.with_extension(format!(
            "tmp-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or_default()
        ));
        let data = serde_json::to_vec_pretty(&self.entries)
            .map_err(|error| ServiceError::InvalidResponse(error.to_string()))?;
        let result = fs::write(&temp, data)
            .and_then(|_| fs::rename(&temp, &self.path))
            .map_err(|error| ServiceError::Transport(error.to_string()));
        drop(lock_file);
        let _ = fs::remove_file(lock);
        result
    }
}

fn cache_key(key: &CacheKey) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        key.library,
        key.package_prefix,
        key.version,
        key.scanner_schema_version,
        key.parser_version
    )
}

#[cfg(test)]
mod tests {
    use super::{CacheEntry, CacheKey, CveCache, CveRecord};

    #[test]
    fn cache_round_trips_versioned_entries() {
        let path = std::env::temp_dir().join(format!("dexprobe-cache-{}.json", std::process::id()));
        let key = CacheKey {
            library: "okhttp".into(),
            package_prefix: "com.squareup.okhttp3".into(),
            version: "unknown".into(),
            scanner_schema_version: 1,
            parser_version: "parser1".into(),
        };
        let mut cache = CveCache::open(&path);
        cache.put(
            &key,
            CacheEntry {
                fetched_at: 1,
                stale: false,
                records: vec![CveRecord {
                    id: "CVE-test".into(),
                    description: "test".into(),
                    cvss: Some(7.0),
                    source_url: "https://nvd.nist.gov/".into(),
                    applicability: "unknown".into(),
                }],
            },
        );
        cache.flush().expect("flush cache");
        let loaded = CveCache::open(&path);
        assert_eq!(loaded.get(&key).expect("cache entry").records.len(), 1);
        std::fs::remove_file(path).expect("remove cache");
    }
}
