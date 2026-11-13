/// core/aggregator.rs — Finding Aggregator.
///
/// Mirror of `core/aggregator.py`. Thin pass-through today; cross-pipeline
/// correlation (dedup, correlation) is planned for Phase 10.
///
/// Public API
/// ----------
///   aggregate(findings_by_pipeline) -> Vec<Finding>
use std::collections::HashMap;

use crate::models::finding::Finding;

/// Flatten per-pipeline `Finding` lists into one combined list.
///
/// Pipeline names are back-filled on any finding that forgot to set `.pipeline`.
pub fn aggregate(findings_by_pipeline: &HashMap<String, Vec<Finding>>) -> Vec<Finding> {
    let mut combined: Vec<Finding> = Vec::new();
    let mut pipelines = findings_by_pipeline.iter().collect::<Vec<_>>();
    pipelines.sort_by_key(|(pipeline, _)| *pipeline);
    for (pipeline_name, findings) in pipelines {
        for mut f in findings.iter().cloned() {
            if f.pipeline.is_empty() {
                f.pipeline = pipeline_name.clone();
            }
            combined.push(f);
        }
    }
    combined
}
