/// pipelines/ — One module per analysis pipeline.
///
/// Mirror of `pipelines/`. Each pipeline receives an `UnpackedApk` and returns
/// `Vec<Finding>`. Nothing here touches the filesystem directly — it reads
/// paths from `session.temp_dir`.
///
/// Activation order (per the project's phase plan):
///   Phase 2  -> manifest
///   Phase 3  -> secrets
///   Phase 4  -> network
///   Phase 5  -> dynamic
///   Phase 6  -> dependencies
///   Phase 7  -> cve
///   Phase 8  -> reachability (extends dependency + cve)
///   Phase 9  -> enrich (LLM)
///   Phase 11 -> report
///
/// Currently all pipelines are stubs until their implementation phase.
///
/// Public API
/// ----------
///   run(name, unpacked) -> Vec<Finding>   (dynamic dispatch by name)
use crate::core::UnpackedApk;
use crate::models::finding::Finding;

/// Dynamically dispatch to the pipeline named by `name`.
///
/// Returns an empty finding list for unknown pipeline names.
pub fn run(name: &str, unpacked: &UnpackedApk) -> Vec<Finding> {
    run_with_mode(name, unpacked, crate::config::AnalysisMode::Online)
}

pub fn run_with_mode(
    name: &str,
    unpacked: &UnpackedApk,
    mode: crate::config::AnalysisMode,
) -> Vec<Finding> {
    match name {
        "manifest" => manifest::run(unpacked),
        "secrets" => secrets::run(unpacked),
        "dependencies" => dependencies::run_with_mode(unpacked, mode),
        "network" => network::run(unpacked),
        "dynamic" => dynamic::run(unpacked),
        _ => {
            crate::core::logger::warn(&format!("Unknown pipeline: {name}"));
            Vec::new()
        }
    }
}

/// Manifest risk profiling pipeline.
pub mod manifest;

/// Secrets, keys, tokens & encoded-credential detection pipeline.
pub mod secrets;

/// Dependency/CVE lookup + library identification pipeline.
pub mod dependencies;

/// Network fingerprinting pipeline (hardcoded URLs, plain HTTP, suspicious domains).
pub mod network;

/// Dynamic class loading & reflection detection pipeline.
pub mod dynamic;
