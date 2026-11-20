use clap::ValueEnum;
use serde::{Deserialize, Serialize};
/// config.rs — Central configuration for the DexProbe APK security scanner.
///
/// Mirror of `config.py`: API keys, Gemini/NVD settings, cache paths,
/// severity thresholds, high-risk Android permissions and library package map.
use std::path::PathBuf;

pub const MAX_ENTRY_COUNT: usize = 10_000;
pub const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_TOTAL_EXTRACTED_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_RETRIES: usize = 3;
pub const REQUEST_DEADLINE_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum AnalysisMode {
    Online,
    Offline,
    CacheOnly,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum PipelineName {
    Manifest,
    Secrets,
    Network,
    Dynamic,
    Dependencies,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum FailPolicy {
    Never,
    Severity,
    Findings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Success,
    Runtime,
    Policy,
}

impl ExitCode {
    pub const fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::Runtime => 1,
            Self::Policy => 2,
        }
    }
}

// ── API Keys ──────────────────────────────────────────────────────────────────

/// Gemini API key (from `GEMINI_API_KEY` env var).
pub fn gemini_api_key() -> String {
    std::env::var("GEMINI_API_KEY").unwrap_or_default()
}

/// Optional NVD API key — raises the rate limit from 5 to 50 requests / 30s
/// (from `NVD_API_KEY` env var).
pub fn nvd_api_key() -> String {
    std::env::var("NVD_API_KEY").unwrap_or_default()
}

// ── Gemini Settings ───────────────────────────────────────────────────────────
pub const GEMINI_MODEL: &str = "gemini-2.5-flash-preview-04-17";
pub const GEMINI_MAX_RETRIES: usize = 3;
pub const GEMINI_RETRY_DELAY_SECS: u64 = 5;
pub const GEMINI_RPM_LIMIT: u64 = 10;

// ── NVD API Settings ──────────────────────────────────────────────────────────
pub const NVD_BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
/// Seconds between requests without API key (5 req/30s).
pub const NVD_RATE_LIMIT_DELAY_SECS: f64 = 6.0;
/// Seconds between requests when a key is present.
pub const NVD_RATE_LIMIT_KEYED_SECS: f64 = 0.6;
pub const NVD_MAX_RETRIES: usize = 3;
pub const CVE_CACHE_TTL_SECS: u64 = 86_400;

// ── Cache / Temp Directories ──────────────────────────────────────────────────

/// Per-project cache dir (`./cache/`).
pub fn cache_dir() -> PathBuf {
    PathBuf::from("cache")
}

/// Cache file for CVE lookups (`./cache/cve_cache.json`).
pub fn cve_cache_file() -> PathBuf {
    PathBuf::from("cache/cve_cache.json")
}

/// Working temp dir for APK extraction (`./temp/`).
pub fn temp_dir() -> PathBuf {
    PathBuf::from("temp")
}

// ── Tool Metadata ─────────────────────────────────────────────────────────────
pub const TOOL_NAME: &str = "DexProbe";
pub const TOOL_VERSION: &str = "0.1.0";

// ── Severity Levels ───────────────────────────────────────────────────────────
pub const SEVERITY_CRITICAL: &str = "CRITICAL";
pub const SEVERITY_HIGH: &str = "HIGH";
pub const SEVERITY_MEDIUM: &str = "MEDIUM";
pub const SEVERITY_LOW: &str = "LOW";
pub const SEVERITY_INFO: &str = "INFO";

/// Severity labels in descending order.
pub const SEVERITY_ORDER: &[&str] = &[
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
];

/// Numeric score implied by each severity label (used by `severity_score`).
pub fn severity_score(label: &str) -> f64 {
    match label {
        SEVERITY_CRITICAL => 9.0,
        SEVERITY_HIGH => 7.0,
        SEVERITY_MEDIUM => 4.0,
        SEVERITY_LOW => 1.0,
        SEVERITY_INFO => 0.0,
        _ => 0.0,
    }
}

// ── High-Risk Android Permissions ────────────────────────────────────────────
pub const HIGH_RISK_PERMISSIONS: &[&str] = &[
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
];

// ── Suspicious TLDs ───────────────────────────────────────────────────────────
pub const SUSPICIOUS_TLDS: &[&str] = &[".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw"];

// ── Known Library Package Prefixes ────────────────────────────────────────────
/// Maps an Android library package prefix to its library name.
pub const LIBRARY_PACKAGE_MAP: phf::Map<&'static str, &'static str> = phf::phf_map! {
    "okhttp3"                    => "okhttp",
    "com.squareup.okhttp"        => "okhttp",
    "retrofit2"                  => "retrofit",
    "com.google.gson"            => "gson",
    "com.google.firebase"        => "firebase",
    "com.google.android.gms"     => "play-services",
    "io.realm"                   => "realm",
    "com.facebook.android"       => "facebook-android-sdk",
    "com.amplitude"              => "amplitude-android",
    "com.mixpanel.android"       => "mixpanel-android",
    "com.jakewharton.timber"     => "timber",
    "io.sentry"                  => "sentry-android",
    "com.airbnb.android"         => "lottie",
    "com.github.bumptech.glide" => "glide",
    "com.squareup.picasso"       => "picasso",
    "io.coil-kt"                 => "coil",
    "org.bouncycastle"           => "bouncycastle",
    "net.sqlcipher"              => "sqlcipher-android",
    "com.appsflyer"              => "appsflyer-android-sdk",
    "com.adjust.sdk"             => "adjust",
    "com.onesignal"              => "onesignal-android-sdk",
    "io.grpc"                    => "grpc-java",
    "com.google.protobuf"        => "protobuf-java",
    "org.jetbrains.kotlin"       => "kotlin-stdlib",
    "androidx.room"              => "room",
    "androidx.work"              => "work-runtime",
    "org.apache.commons"         => "commons-lang",
    "com.fasterxml.jackson"      => "jackson-databind",
    "io.reactivex"               => "rxjava",
};
