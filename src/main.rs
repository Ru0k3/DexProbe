#![allow(dead_code)]

use std::path::PathBuf;

use clap::Parser;

use crate::config::{AnalysisMode, FailPolicy, TOOL_NAME, TOOL_VERSION};

mod config;
mod core;
mod llm;
mod models;
mod output;
mod pipelines;
mod services;

#[derive(Debug, Parser)]
#[command(name = "dexprobe", version = TOOL_VERSION, about = "Android APK security intelligence scanner")]
struct CliArgs {
    apk_file: PathBuf,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(long)]
    sarif: bool,
    #[arg(long, value_enum)]
    mode: Option<AnalysisMode>,
    #[arg(long, value_enum)]
    fail_on: Option<FailPolicy>,
    #[arg(long)]
    max_findings: Option<usize>,
    #[arg(long)]
    skip_llm: bool,
    #[arg(long)]
    pipeline: Option<String>,
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug)]
struct CliConfig {
    mode: AnalysisMode,
    fail_policy: FailPolicy,
    max_findings: Option<usize>,
    output: Option<PathBuf>,
    sarif: bool,
    pipeline: Option<String>,
    skip_llm: bool,
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let args = CliArgs::parse();
    if args.sarif && args.output.is_none() {
        anyhow::bail!("--sarif requires --output <path>");
    }
    let config = CliConfig {
        mode: args
            .mode
            .unwrap_or_else(|| env_mode().unwrap_or(AnalysisMode::Online)),
        fail_policy: args
            .fail_on
            .or_else(env_fail_policy)
            .unwrap_or(FailPolicy::Never),
        max_findings: args
            .max_findings
            .or_else(|| std::env::var("DEXPROBE_MAX_FINDINGS").ok()?.parse().ok()),
        output: args.output.clone(),
        sarif: args.sarif,
        pipeline: args.pipeline.clone(),
        skip_llm: args.skip_llm,
        verbose: args.verbose,
    };
    let mut unpacked = core::open_apk(&args.apk_file, config.verbose)?;
    if let Some(name) = config.pipeline.as_deref()
        && !core::runner::ALL_PIPELINES.contains(&name)
    {
        core::cleanup(&mut unpacked);
        anyhow::bail!("unknown pipeline '{name}'");
    }
    let selected: Vec<&str> = config
        .pipeline
        .as_deref()
        .map(|name| vec![name])
        .unwrap_or_else(|| core::runner::ALL_PIPELINES.to_vec());
    let result = (|| -> anyhow::Result<()> {
        let grouped = core::runner::run_pipelines(&unpacked, &selected, config.mode);
        let mut findings = core::scorer::score_findings(core::aggregator::aggregate(&grouped));
        let (exceeded, threshold) =
            policy_result(&findings, config.fail_policy, config.max_findings);
        if let Some(max) = config.max_findings {
            findings.truncate(max);
        }
        let findings = llm::enricher::enrich(
            findings,
            config.skip_llm || config.mode != AnalysisMode::Online,
        );
        let meta = output::report::Meta {
            tool: TOOL_NAME.to_string(),
            version: TOOL_VERSION.to_string(),
            apk_path: args.apk_file.display().to_string(),
            scan_time: chrono::Utc::now().to_rfc3339(),
            skip_llm: config.skip_llm || config.mode != AnalysisMode::Online,
            pipeline: config.pipeline.clone(),
        };
        output::report::render_terminal(&findings, &meta);
        if let Some(path) = config.output.as_deref() {
            if config.sarif {
                output::report::export_sarif(&findings, &meta, path)?;
            } else {
                output::report::export_json(
                    &findings,
                    &meta,
                    path,
                    &format!("{:?}", config.fail_policy).to_lowercase(),
                    threshold.clone(),
                    exceeded,
                )?;
            }
        }
        if exceeded {
            std::process::exit(crate::config::ExitCode::Policy.code());
        }
        Ok(())
    })();
    core::cleanup(&mut unpacked);
    result
}

fn env_mode() -> Option<AnalysisMode> {
    match std::env::var("DEXPROBE_MODE").ok()?.as_str() {
        "online" => Some(AnalysisMode::Online),
        "offline" => Some(AnalysisMode::Offline),
        "cache-only" => Some(AnalysisMode::CacheOnly),
        _ => None,
    }
}

fn env_fail_policy() -> Option<FailPolicy> {
    match std::env::var("DEXPROBE_FAIL_ON").ok()?.as_str() {
        "never" => Some(FailPolicy::Never),
        "severity" => Some(FailPolicy::Severity),
        "findings" => Some(FailPolicy::Findings),
        _ => None,
    }
}

fn policy_result(
    findings: &[crate::models::finding::Finding],
    policy: FailPolicy,
    max_findings: Option<usize>,
) -> (bool, Option<String>) {
    match policy {
        FailPolicy::Never => (false, None),
        FailPolicy::Severity => {
            let exceeded = findings.iter().any(|finding| {
                finding.score >= 7.0 && !finding.tags.iter().any(|tag| tag == "nvd")
            });
            (exceeded, Some("HIGH".into()))
        }
        FailPolicy::Findings => {
            let threshold = max_findings.unwrap_or(0);
            (findings.len() > threshold, Some(threshold.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::policy_result;
    use crate::config::FailPolicy;
    use crate::models::finding::Finding;

    #[test]
    fn keyword_only_nvd_candidates_do_not_fail_severity_policy() {
        let mut candidate = Finding::new("dependencies", "Potential CVE", "unverified");
        candidate.score = 9.8;
        candidate.tags.push("nvd".into());
        assert!(!policy_result(&[candidate], FailPolicy::Severity, None).0);

        let mut confirmed_signal = Finding::new("manifest", "Debuggable", "confirmed");
        confirmed_signal.score = 7.0;
        assert!(policy_result(&[confirmed_signal], FailPolicy::Severity, None).0);
    }
}
