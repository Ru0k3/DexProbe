# DexProbe

Rust-based Android APK security intelligence scanner.

## Status

The Rust CLI validates and unpacks APK ZIP archives, parses binary AXML and DEX
files, scans manifest/resources/DEX content through manifest, secrets, network,
dynamic-loading, and dependency pipelines, ranks findings, prints a terminal
report, and optionally writes a versioned JSON report. Dynamic-loading and
dependency presence findings use parser-backed DEX class/method evidence.
CVE reachability is intentionally reported as unverified until a validated
call graph maps application code to vulnerable methods.

```bash
cargo run -- --help
cargo run -- --skip-llm --output report.json app.apk
cargo run -- --skip-llm --pipeline manifest app.apk
cargo run -- --mode offline --fail-on severity --output report.json app.apk
```

`--mode` accepts `online`, `offline`, or `cache-only`. Online mode may use
`GEMINI_API_KEY` and `NVD_API_KEY`; offline mode never calls those services, and
cache-only mode only uses existing CVE cache entries. `DEXPROBE_MODE`,
`DEXPROBE_FAIL_ON`, and `DEXPROBE_MAX_FINDINGS` provide environment defaults;
command-line values take precedence.

`--fail-on severity` exits with code `2` when a HIGH-or-more finding exists.
`--fail-on findings --max-findings N` exits with code `2` when the scan produces
more than `N` findings. Runtime and input failures exit with code `1`; success
exits with code `0`.

The scanner does not execute the application, infer product purpose, or claim
CVE reachability without parser-backed call-graph evidence. Evidence in JSON
and terminal output is redacted by default.

Generated reports, APKs, extraction directories, caches, and Cargo build
artifacts are ignored by Git. Never commit API keys or downloaded APKs.