pub mod aggregator;
pub mod dex;
/// core/ — APK unpacking, pipeline execution, aggregation & scoring.
pub mod error;
pub mod logger;
pub mod runner;
pub mod scorer;
pub mod unpacker;

pub use unpacker::{UnpackedApk, cleanup, open_apk};
