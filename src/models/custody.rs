use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::EvidenceFile;

/// Fixed wording required by the constitution and FR-013.
pub const DISCLAIMER: &str =
    "Findings are heuristic triage indicators, not verdicts or legal proof. \
SHA-256 digests certify only the bytes read during this execution and do not prove that a file \
was unchanged before or after the run. This report is not a substitute for a full forensic \
investigation.";

/// Run-level provenance attached to every findings report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyManifest {
    /// Execution time in UTC.
    pub generated_at: DateTime<Utc>,
    /// Best-effort hostname; `None` when no local source is readable.
    pub hostname: Option<String>,
    /// Version of the binary that produced the report.
    pub tool_version: String,
    /// SHA-256 of the serialized effective configuration.
    pub config_sha256: String,
    /// Effective configuration used by this run, as serialized TOML.
    pub effective_config: String,
    /// Every resolved input, including files that could not be read.
    pub files: Vec<EvidenceFile>,
    /// Heuristic-triage disclaimer shown by both export formats.
    pub disclaimer: String,
}

impl CustodyManifest {
    /// Builds a manifest for one completed analysis run.
    #[must_use]
    pub fn new(files: Vec<EvidenceFile>, tool_version: &str, effective_config: String) -> Self {
        let config_sha256 = crate::core::hash::sha256_bytes(effective_config.as_bytes());
        Self {
            generated_at: Utc::now(),
            hostname: best_effort_hostname(),
            tool_version: tool_version.to_string(),
            config_sha256,
            effective_config,
            files,
            disclaimer: DISCLAIMER.to_string(),
        }
    }

    /// Placeholder manifest for an empty report.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            generated_at: Utc::now(),
            hostname: best_effort_hostname(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            config_sha256: String::new(),
            effective_config: String::new(),
            files: Vec::new(),
            disclaimer: DISCLAIMER.to_string(),
        }
    }
}

/// Reads the host name from local files, falling back to the environment.
///
/// This never touches the network and never requires elevated privileges.
#[must_use]
pub fn best_effort_hostname() -> Option<String> {
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(raw) = std::fs::read_to_string(path) {
            let name = raw.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    std::env::var("HOSTNAME")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_always_has_disclaimer() {
        let manifest = CustodyManifest::empty();
        assert_eq!(manifest.disclaimer, DISCLAIMER);
        assert_ne!(manifest.tool_version, "");
    }

    #[test]
    fn test_manifest_keeps_input_order_and_errors() {
        let files = vec![EvidenceFile {
            path: "/var/log/ufw.log".to_string(),
            canonical_path: "/var/log/ufw.log".to_string(),
            sha256: "abc".to_string(),
            size_bytes: 10,
            decompressed_bytes: 10,
            modified_at: None,
            compressed: false,
            from_cache: false,
            parse_stats: super::super::ParseStats::default(),
            error: None,
        }];

        let manifest =
            CustodyManifest::new(files, "0.3.0", "[thresholds]\nmin_score = 25\n".to_string());
        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].path, "/var/log/ufw.log");
        assert_eq!(manifest.tool_version, "0.3.0");
        assert_eq!(manifest.effective_config, "[thresholds]\nmin_score = 25\n");
        assert_eq!(manifest.config_sha256.len(), 64);
    }
}
