use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

#[test]
fn scans_generated_apk_and_keeps_sarif_locations_durable() {
    let id = std::process::id();
    let apk_path = std::env::temp_dir().join(format!("dexprobe-fixture-{id}.apk"));
    let report_path = std::env::temp_dir().join(format!("dexprobe-fixture-{id}.sarif"));
    let mut manifest = Cursor::new(Vec::new());
    apk::res::Chunk::Xml(vec![
        apk::res::Chunk::StringPool(
            vec![
                "manifest".into(),
                "package".into(),
                "com.example.fixture".into(),
            ],
            vec![],
        ),
        apk::res::Chunk::XmlStartElement(
            apk::res::ResXmlNodeHeader::default(),
            apk::res::ResXmlStartElement {
                name: 0,
                attribute_count: 1,
                ..Default::default()
            },
            vec![apk::res::ResXmlAttribute {
                namespace: -1,
                name: 1,
                raw_value: 2,
                typed_value: apk::res::ResValue {
                    size: 8,
                    res0: 0,
                    data_type: 3,
                    data: 2,
                },
            }],
        ),
    ])
    .write(&mut manifest)
    .expect("write fixture manifest");

    let file = fs::File::create(&apk_path).expect("create APK fixture");
    let mut zip = ZipWriter::new(file);
    for (name, content) in [
        ("AndroidManifest.xml", manifest.get_ref().as_slice()),
        (
            "assets/aboutlibraries.json",
            b"http://docs.example.test".as_slice(),
        ),
        (
            "assets/files/LICENSES/license.txt",
            b"http://license.example.test".as_slice(),
        ),
        ("assets/api.json", b"http://api.example.test".as_slice()),
    ] {
        zip.start_file(name, SimpleFileOptions::default())
            .expect("start APK entry");
        zip.write_all(content).expect("write APK entry");
    }
    zip.finish().expect("finish APK fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_dexprobe"))
        .args(["--mode", "offline", "--skip-llm", "--sarif", "--output"])
        .arg(&report_path)
        .arg(&apk_path)
        .output()
        .expect("run DexProbe");
    let report: serde_json::Value = fs::read(&report_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .expect("read SARIF report");
    let _ = fs::remove_file(&apk_path);
    let _ = fs::remove_file(&report_path);
    assert!(
        output.status.success(),
        "DexProbe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let results = report["runs"][0]["results"]
        .as_array()
        .expect("SARIF results");
    let network = results
        .iter()
        .filter(|result| result["ruleId"] == "network")
        .collect::<Vec<_>>();
    assert_eq!(network.len(), 1);
    assert_eq!(network[0]["properties"]["apk_location"], "assets/api.json");
    assert_eq!(
        network[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        apk_path.to_string_lossy().as_ref()
    );
}

#[test]
fn validates_optional_external_apks_when_configured() {
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
