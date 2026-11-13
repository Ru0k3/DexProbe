use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;

#[test]
fn validates_external_apks_when_configured() {
    let Ok(directory) = std::env::var("DEXPROBE_APK_DIR") else {
        eprintln!("DEXPROBE_APK_DIR not set; external APK validation skipped");
        return;
    };
    let directory = Path::new(&directory);
    let mut results = Vec::new();
    let entries = fs::read_dir(directory).expect("read DEXPROBE_APK_DIR");
    for entry in entries {
        let path = entry.expect("read APK directory entry").path();
        if path.extension().and_then(|value| value.to_str()) != Some("apk") {
            continue;
        }
        let digest = sha256(&path);
        let report_path = std::env::temp_dir().join(format!(
            "dexprobe-external-{}-{}.json",
            std::process::id(),
            results.len()
        ));
        let output = Command::new(env!("CARGO_BIN_EXE_dexprobe"))
            .args(["--mode", "offline", "--skip-llm"])
            .args(["--output"])
            .arg(&report_path)
            .arg(&path)
            .output()
            .expect("run dexprobe");
        let report = String::from_utf8_lossy(&output.stdout);
        let report_json: serde_json::Value = fs::read(&report_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        results.push(serde_json::json!({
            "filename": path.file_name().and_then(|value| value.to_str()).unwrap_or("unknown"),
            "sha256": digest,
            "scanner_version": env!("CARGO_PKG_VERSION"),
            "pass": output.status.success(),
            "finding_count": report_json["summary"]["total"].as_u64().unwrap_or(0),
            "stdout_bytes": report.len(),
            "stderr_bytes": output.stderr.len(),
        }));
        let _ = fs::remove_file(report_path);
        assert!(
            output.status.success(),
            "external APK failed: {}",
            path.display()
        );
    }
    let output = serde_json::to_vec_pretty(&results).expect("serialize external results");
    fs::write("/tmp/dexprobe-external-results.json", output).expect("write external result file");
}

fn sha256(path: &Path) -> String {
    let mut file = fs::File::open(path).expect("open APK");
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).expect("read APK");
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    format!("{:x}", hasher.finalize())
}
