use crate::core::UnpackedApk;
use crate::models::finding::Finding;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PIPELINE_NAME: &str = "dependencies";

pub fn run(unpacked: &UnpackedApk) -> Vec<Finding> {
    run_with_mode(unpacked, crate::config::AnalysisMode::Online)
}

pub fn run_with_mode(unpacked: &UnpackedApk, mode: crate::config::AnalysisMode) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut libraries = BTreeSet::new();
    for path in &unpacked.dex_files {
        let Ok(dex) = crate::core::dex::parse_file(path) else {
            continue;
        };
        for (prefix, library) in crate::config::LIBRARY_PACKAGE_MAP.entries() {
            if dex
                .class_defs
                .iter()
                .any(|class| crate::core::dex::class_matches_package_prefix(&class.name, prefix))
            {
                libraries.insert((*library).to_string());
                let mut finding = Finding::new(
                    PIPELINE_NAME,
                    format!("Dependency detected: {library}"),
                    "A known third-party package prefix is present; version and CVE status require metadata or NVD enrichment.",
                );
                finding.score = 1.0;
                finding.location = path.display().to_string();
                finding.evidence = (*prefix).to_string();
                finding.redacted_evidence = (*prefix).to_string();
                finding.evidence_source = "parsed DEX class definition".into();
                finding.precision = crate::models::finding::EvidencePrecision::Exact;
                finding.confidence = crate::models::finding::Confidence::Confirmed;
                findings.push(finding);
            }
        }
    }
    let online = mode == crate::config::AnalysisMode::Online;
    let mut cache = load_cache();
    let now = unix_now();
    let mut cache_changed = false;
    let mut last_nvd_request = None;
    for library in libraries {
        let cache_key = format!("{library}@unknown:schema1:parser1");
        let cached = cache.get(&cache_key).cloned();
        if let Some(entry) = &cached
            && (!online || now.saturating_sub(entry.fetched_at) < crate::config::CVE_CACHE_TTL_SECS)
        {
            findings.extend(normalize_cached_findings(entry.findings.clone()));
            continue;
        }
        if online {
            match lookup_nvd(
                &library,
                prefix_for_library(&library),
                &mut last_nvd_request,
            ) {
                Ok(cves) => {
                    let mut cves = cves;
                    apply_reachability(&mut cves, unpacked, prefix_for_library(&library));
                    findings.extend(cves.clone());
                    cache.insert(
                        cache_key,
                        CacheEntry {
                            fetched_at: now,
                            findings: cves,
                        },
                    );
                    cache_changed = true;
                }
                Err(error) => {
                    crate::core::logger::warn(&format!("NVD lookup failed: {error}"));
                    if let Some(entry) = cached {
                        findings.extend(mark_stale(entry.findings));
                    }
                }
            }
        } else if let Some(entry) = cached {
            findings.extend(mark_stale(entry.findings));
        }
    }
    if cache_changed {
        save_cache(&cache);
    }
    findings
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    fetched_at: u64,
    findings: Vec<Finding>,
}

fn load_cache() -> HashMap<String, CacheEntry> {
    let path = crate::config::cve_cache_file();
    let Ok(bytes) = fs::read(path) else {
        return HashMap::new();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn save_cache(cache: &HashMap<String, CacheEntry>) {
    let path = crate::config::cve_cache_file();
    let Some(parent) = path.parent() else {
        return;
    };
    if let Err(error) = fs::create_dir_all(parent) {
        crate::core::logger::warn(&format!("Could not create CVE cache directory: {error}"));
        return;
    }

    let Ok(bytes) = serde_json::to_vec_pretty(cache) else {
        crate::core::logger::warn("Could not serialize CVE cache.");
        return;
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temporary = path.with_extension(format!("json.{}.{nonce}.tmp", std::process::id()));
    // shortcut: concurrent scans can replace each other's cache entries; cache misses only repeat NVD lookups.
    let result = fs::write(&temporary, bytes).and_then(|_| fs::rename(&temporary, &path));
    if let Err(error) = result {
        crate::core::logger::warn(&format!("Could not update CVE cache: {error}"));
    } else {
        crate::core::logger::info(&format!("CVE cache updated: {}", path.display()));
    }
}

fn mark_stale(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings = normalize_cached_findings(findings);
    for finding in &mut findings {
        if !finding.tags.iter().any(|tag| tag == "cache_stale") {
            finding.tags.push("cache_stale".into());
        }
        finding.confidence = crate::models::finding::Confidence::Unknown;
    }
    findings
}

fn normalize_cached_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    for finding in &mut findings {
        if finding.tags.iter().any(|tag| tag == "nvd") {
            if !finding.tags.iter().any(|tag| tag.starts_with("nvd_cvss=")) {
                finding.tags.push(format!("nvd_cvss={:.1}", finding.score));
            }
            finding.score = 0.0;
        }
    }
    findings
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn lookup_nvd(
    library: &str,
    package_prefix: &str,
    last_request: &mut Option<Instant>,
) -> anyhow::Result<Vec<Finding>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(crate::config::REQUEST_DEADLINE_SECS))
        .build()?;
    let api_key = std::env::var("NVD_API_KEY").unwrap_or_default();
    let interval = Duration::from_secs_f64(if api_key.is_empty() {
        crate::config::NVD_RATE_LIMIT_DELAY_SECS
    } else {
        crate::config::NVD_RATE_LIMIT_KEYED_SECS
    });
    let mut last_error = None;
    for attempt in 0..=crate::config::NVD_MAX_RETRIES {
        let retry_delay = if attempt == 0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(
                (interval.as_secs_f64() * 2_u32.pow((attempt - 1) as u32) as f64).min(60.0),
            )
        };
        let delay = nvd_request_delay(
            last_request.map(|last| last.elapsed()),
            interval,
            retry_delay,
        );
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        let mut request = client
            .get(crate::config::NVD_BASE_URL)
            .query(&[("keywordSearch", library), ("resultsPerPage", "20")]);
        if !api_key.is_empty() {
            request = request.header("apiKey", &api_key);
        }
        let _rate_limit_lock = lock_nvd_rate_limit(interval)?;
        let response = request.send();
        *last_request = Some(Instant::now());
        match response {
            Ok(response) if response.status().is_success() => {
                if response
                    .content_length()
                    .is_some_and(|size| size > crate::config::MAX_REQUEST_BYTES)
                {
                    anyhow::bail!("NVD response exceeded configured size limit");
                }
                let mut bytes = Vec::new();
                response
                    .take(crate::config::MAX_REQUEST_BYTES + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() as u64 > crate::config::MAX_REQUEST_BYTES {
                    anyhow::bail!("NVD response exceeded configured size limit");
                }
                let payload: Value = serde_json::from_slice(&bytes)?;
                return parse_nvd_findings(library, package_prefix, &payload);
            }
            Ok(response) => {
                last_error = Some(anyhow::anyhow!("NVD returned {}", response.status()));
            }
            Err(error) => last_error = Some(error.into()),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("NVD lookup failed")))
}

fn lock_nvd_rate_limit(interval: Duration) -> anyhow::Result<File> {
    let path = PathBuf::from(format!(
        "{}.rate-limit",
        crate::config::cve_cache_file().display()
    ));
    lock_nvd_rate_limit_at(&path, interval)
}

fn lock_nvd_rate_limit_at(path: &std::path::Path, interval: Duration) -> anyhow::Result<File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    // Keep the lock through the request; concurrent processes then reserve starts in order.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut stored = String::new();
    file.read_to_string(&mut stored)?;
    let previous = stored.trim().parse::<u128>().unwrap_or_default();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let wait = interval
        .as_millis()
        .saturating_sub(now.saturating_sub(previous));
    if wait > 0 {
        std::thread::sleep(Duration::from_millis(wait.min(u64::MAX as u128) as u64));
    }
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    writeln!(
        file,
        "{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    )?;
    file.flush()?;
    Ok(file)
}

fn nvd_request_delay(
    elapsed_since_last_request: Option<Duration>,
    interval: Duration,
    retry_delay: Duration,
) -> Duration {
    elapsed_since_last_request
        .map(|elapsed| interval.saturating_sub(elapsed).max(retry_delay))
        .unwrap_or(retry_delay)
}

fn parse_nvd_findings(
    library: &str,
    package_prefix: &str,
    payload: &Value,
) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for item in payload["vulnerabilities"].as_array().into_iter().flatten() {
        let cve = &item["cve"];
        let id = cve["id"].as_str().unwrap_or("unknown-CVE");
        let score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            .as_f64()
            .unwrap_or(5.0);
        let mut finding = Finding::new(
            PIPELINE_NAME,
            format!("Potential CVE for {library}: {id}"),
            cve["descriptions"][0]["value"]
                .as_str()
                .unwrap_or("NVD reported a vulnerability for this dependency."),
        );
        finding.score = 0.0;
        finding.location = "dependency metadata".into();
        finding.evidence = id.into();
        finding.redacted_evidence = id.into();
        finding.evidence_source = "NVD response".into();
        finding.cve_ids.push(id.into());
        finding.reachability = crate::models::finding::Reachability::Unverified;
        finding.confidence = crate::models::finding::Confidence::Unknown;
        finding.tags.push("nvd".into());
        finding.tags.push(format!("nvd_cvss={score:.1}"));
        finding
            .tags
            .push(format!("package_prefix={package_prefix}"));
        findings.push(finding);
    }

    Ok(findings)
}

fn prefix_for_library(library: &str) -> &str {
    crate::config::LIBRARY_PACKAGE_MAP
        .entries()
        .find_map(|(prefix, name)| (*name == library).then_some(*prefix))
        .unwrap_or(library)
}

fn apply_reachability(findings: &mut [Finding], unpacked: &UnpackedApk, package_prefix: &str) {
    for finding in findings {
        let Some(method) = extract_vulnerable_method(&finding.detail) else {
            finding.reachability = crate::models::finding::Reachability::Unverified;
            continue;
        };
        let reachable = unpacked.dex_files.iter().any(|path| {
            crate::core::dex::parse_file(path)
                .map(|dex| {
                    crate::core::dex::reachable_library_method(&dex, package_prefix, Some(&method))
                })
                .unwrap_or(false)
        });
        finding.reachability = if reachable {
            crate::models::finding::Reachability::Reachable
        } else {
            crate::models::finding::Reachability::PresentNotReachable
        };
    }
}

fn extract_vulnerable_method(description: &str) -> Option<String> {
    let start = description.find('L')?;
    let end = description[start..].find('(')? + start;
    let candidate = &description[start..end];
    candidate.contains(";->").then(|| candidate.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        extract_vulnerable_method, lock_nvd_rate_limit_at, normalize_cached_findings,
        nvd_request_delay, parse_nvd_findings,
    };
    use crate::models::finding::Finding;
    use std::time::Duration;

    #[test]
    fn only_extracts_explicit_dalvik_method_signatures() {
        assert_eq!(
            extract_vulnerable_method("issue in Lcom/example/Client;->send(Ljava/lang/String;)"),
            Some("Lcom/example/Client;->send".into())
        );
        assert!(extract_vulnerable_method("issue in the send method").is_none());
    }

    #[test]
    fn keyword_candidates_keep_cvss_as_advisory_metadata() {
        let payload = serde_json::json!({
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2099-1234",
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                    "descriptions": [{"value": "Candidate description"}]
                }
            }]
        });
        let finding = parse_nvd_findings("okhttp", "okhttp3", &payload)
            .unwrap()
            .remove(0);
        assert_eq!(finding.score, 0.0);
        assert!(finding.tags.iter().any(|tag| tag == "nvd_cvss=9.8"));
        assert_eq!(
            finding.confidence,
            crate::models::finding::Confidence::Unknown
        );
    }

    #[test]
    fn old_cached_candidates_are_downgraded_and_keep_their_cvss() {
        let mut candidate = Finding::new("dependencies", "Potential CVE", "cached");
        candidate.score = 9.8;
        candidate.tags.push("nvd".into());
        let normalized = normalize_cached_findings(vec![candidate]).remove(0);
        assert_eq!(normalized.score, 0.0);
        assert!(normalized.tags.iter().any(|tag| tag == "nvd_cvss=9.8"));
    }

    #[test]
    fn nvd_delay_enforces_spacing_and_retry_backoff() {
        let interval = Duration::from_secs(6);
        assert_eq!(
            nvd_request_delay(None, interval, Duration::ZERO),
            Duration::ZERO
        );
        assert_eq!(
            nvd_request_delay(Some(Duration::from_secs(2)), interval, Duration::ZERO),
            Duration::from_secs(4)
        );
        assert_eq!(
            nvd_request_delay(Some(interval), interval, Duration::from_secs(12)),
            Duration::from_secs(12)
        );
    }

    #[test]
    fn nvd_rate_limit_lock_spaces_concurrent_process_handles() {
        let path = std::env::temp_dir().join(format!(
            "dexprobe-rate-limit-{}-{}.lock",
            std::process::id(),
            super::unix_now()
        ));
        let interval = Duration::from_millis(80);
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let _lock = lock_nvd_rate_limit_at(&path, interval).unwrap();
                    std::time::Instant::now()
                })
            })
            .collect();
        let mut finished: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        finished.sort();
        assert!(finished[1].duration_since(finished[0]) >= interval - Duration::from_millis(10));
        let _ = std::fs::remove_file(path);
    }
}
