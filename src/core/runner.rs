use std::collections::HashMap;

use crate::core::logger;
use crate::models::finding::Finding;
use crate::pipelines;

pub const ALL_PIPELINES: &[&str] = &["manifest", "secrets", "dependencies", "network", "dynamic"];

pub fn run_pipelines(
    unpacked: &crate::core::UnpackedApk,
    to_run: &[&str],
    mode: crate::config::AnalysisMode,
) -> HashMap<String, Vec<Finding>> {
    let mut combined = HashMap::new();
    logger::section("ANALYSIS PIPELINES", 54);
    for name in to_run {
        logger::step(&format!("Running pipeline: {name}"));
        let results = pipelines::run_with_mode(name, unpacked, mode);
        logger::ok(&format!("{name} -> {} finding(s)", results.len()));
        combined.insert((*name).to_string(), results);
    }
    combined
}
