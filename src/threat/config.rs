use std::collections::HashSet;
use std::str::FromStr;

use anyhow::Context;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Heuristic thresholds. The `*_per_hour` keys keep their historical names but
/// are evaluated over the matching configurable window (60 minutes by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    pub scan_ports_per_hour: u32,
    pub scan_hosts_per_hour: u32,
    pub bruteforce_attempts_per_hour: u64,
    pub bruteforce_attempts_per_day: u64,
    pub distributed_sources_per_hour: u32,
    pub persistence_min_days: u32,
    pub persistence_min_blocks: u64,
    pub subnet_min_sources: u32,
    pub min_score: u8,
    pub scan_window_minutes: u32,
    pub bruteforce_window_minutes: u32,
    pub distributed_window_minutes: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            scan_ports_per_hour: 10,
            scan_hosts_per_hour: 10,
            bruteforce_attempts_per_hour: 20,
            bruteforce_attempts_per_day: 50,
            distributed_sources_per_hour: 20,
            persistence_min_days: 3,
            persistence_min_blocks: 20,
            subnet_min_sources: 5,
            min_score: 25,
            scan_window_minutes: 60,
            bruteforce_window_minutes: 60,
            distributed_window_minutes: 60,
        }
    }
}

/// Thresholds that promote coverage anomalies to evidence-integrity findings.
///
/// A value of `0` disables that check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IntegrityConfig {
    pub missing_hours: u32,
    pub out_of_order_lines: u64,
    pub future_entries: u64,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            missing_hours: 24,
            out_of_order_lines: 10,
            future_entries: 1,
        }
    }
}

/// Prefix lengths used to group sources into networks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SubnetConfig {
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
}

impl Default for SubnetConfig {
    fn default() -> Self {
        Self {
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        }
    }
}

/// Destination ports considered administrative or high value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PortsConfig {
    pub admin: Vec<u16>,
}

impl Default for PortsConfig {
    fn default() -> Self {
        Self {
            admin: vec![
                21, 22, 23, 25, 53, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080,
                8443, 9200, 11211, 27017,
            ],
        }
    }
}

impl PortsConfig {
    #[must_use]
    pub fn admin_set(&self) -> HashSet<u16> {
        self.admin.iter().copied().collect()
    }
}

/// Hard limits applied while reading input files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    /// Maximum decompressed size for one `.gz` input, in bytes.
    pub max_decompressed_bytes: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_decompressed_bytes: crate::core::DEFAULT_MAX_DECOMPRESSED_BYTES,
        }
    }
}

/// CIDR ranges that should never be reported as threats.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowlistConfig {
    pub cidrs: Vec<String>,
}

/// Weights for the 0-100 risk score.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScoringConfig {
    pub volume_weight: u32,
    pub ports_weight: u32,
    pub admin_weight: u32,
    pub persistence_weight: u32,
    pub finding_weight: u32,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            volume_weight: 8,
            ports_weight: 2,
            admin_weight: 1,
            persistence_weight: 3,
            finding_weight: 10,
        }
    }
}

/// Full analysis configuration, loaded from an explicit TOML file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisConfig {
    pub thresholds: Thresholds,
    pub limits: LimitsConfig,
    pub subnets: SubnetConfig,
    pub ports: PortsConfig,
    pub allowlist: AllowlistConfig,
    pub scoring: ScoringConfig,
    pub integrity: IntegrityConfig,
}

impl AnalysisConfig {
    /// Loads the configuration from `path`, or returns the defaults.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, is not valid TOML, or
    /// contains invalid values.
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file '{path}'"))?;
        let config: Self = toml::from_str(&text)
            .with_context(|| format!("Failed to parse config file '{path}'"))?;
        config
            .validate()
            .with_context(|| format!("Invalid config file '{path}'"))?;
        Ok(config)
    }

    /// Parses and validates a TOML document.
    ///
    /// # Errors
    ///
    /// Returns an error when the TOML is invalid or a value is out of range.
    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(text).context("Failed to parse TOML")?;
        config.validate()?;
        Ok(config)
    }

    /// Checks every configurable value that could break the analysis.
    ///
    /// # Errors
    ///
    /// Returns an error describing the first invalid value.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.thresholds.scan_ports_per_hour > 0,
            "thresholds.scan_ports_per_hour must be greater than zero"
        );
        anyhow::ensure!(
            self.thresholds.scan_hosts_per_hour > 0,
            "thresholds.scan_hosts_per_hour must be greater than zero"
        );
        anyhow::ensure!(
            self.thresholds.bruteforce_attempts_per_hour > 0,
            "thresholds.bruteforce_attempts_per_hour must be greater than zero"
        );
        anyhow::ensure!(
            self.thresholds.bruteforce_attempts_per_day > 0,
            "thresholds.bruteforce_attempts_per_day must be greater than zero"
        );
        anyhow::ensure!(
            self.thresholds.distributed_sources_per_hour > 0,
            "thresholds.distributed_sources_per_hour must be greater than zero"
        );
        anyhow::ensure!(
            self.thresholds.persistence_min_days > 0,
            "thresholds.persistence_min_days must be greater than zero"
        );
        anyhow::ensure!(
            self.thresholds.persistence_min_blocks > 0,
            "thresholds.persistence_min_blocks must be greater than zero"
        );
        anyhow::ensure!(
            self.thresholds.subnet_min_sources > 0,
            "thresholds.subnet_min_sources must be greater than zero"
        );
        anyhow::ensure!(
            self.limits.max_decompressed_bytes > 0,
            "limits.max_decompressed_bytes must be greater than zero"
        );
        anyhow::ensure!(
            self.subnets.ipv4_prefix <= 32,
            "subnets.ipv4_prefix must be between 0 and 32"
        );
        anyhow::ensure!(
            self.subnets.ipv6_prefix <= 128,
            "subnets.ipv6_prefix must be between 0 and 128"
        );
        for (key, value) in [
            (
                "thresholds.scan_window_minutes",
                self.thresholds.scan_window_minutes,
            ),
            (
                "thresholds.bruteforce_window_minutes",
                self.thresholds.bruteforce_window_minutes,
            ),
            (
                "thresholds.distributed_window_minutes",
                self.thresholds.distributed_window_minutes,
            ),
        ] {
            anyhow::ensure!(
                (1..=10_080).contains(&value),
                "{key} must be between 1 and 10080 minutes"
            );
        }
        for cidr in &self.allowlist.cidrs {
            IpNet::from_str(cidr)
                .with_context(|| format!("allowlist.cidrs contains an invalid CIDR: '{cidr}'"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_match_plan() {
        let config = AnalysisConfig::default();
        assert_eq!(config.thresholds.scan_ports_per_hour, 10);
        assert_eq!(config.thresholds.scan_hosts_per_hour, 10);
        assert_eq!(config.thresholds.bruteforce_attempts_per_hour, 20);
        assert_eq!(config.thresholds.bruteforce_attempts_per_day, 50);
        assert_eq!(config.thresholds.distributed_sources_per_hour, 20);
        assert_eq!(config.thresholds.persistence_min_days, 3);
        assert_eq!(config.thresholds.persistence_min_blocks, 20);
        assert_eq!(config.thresholds.subnet_min_sources, 5);
        assert_eq!(config.thresholds.min_score, 25);
        assert_eq!(config.thresholds.scan_window_minutes, 60);
        assert_eq!(config.thresholds.bruteforce_window_minutes, 60);
        assert_eq!(config.thresholds.distributed_window_minutes, 60);
        assert_eq!(config.integrity.missing_hours, 24);
        assert_eq!(config.integrity.out_of_order_lines, 10);
        assert_eq!(config.integrity.future_entries, 1);
        assert_eq!(config.subnets.ipv4_prefix, 24);
        assert_eq!(config.subnets.ipv6_prefix, 64);
        assert!(config.ports.admin.contains(&22));
        assert_eq!(config.allowlist.cidrs.len(), 0);
        assert_eq!(config.limits.max_decompressed_bytes, 4 * 1024 * 1024 * 1024);
        assert_eq!(config.scoring.volume_weight, 8);
        assert_eq!(config.scoring.ports_weight, 2);
        assert_eq!(config.scoring.admin_weight, 1);
        assert_eq!(config.scoring.persistence_weight, 3);
        assert_eq!(config.scoring.finding_weight, 10);
    }

    #[test]
    fn test_partial_config_keeps_defaults() {
        let config = AnalysisConfig::from_toml(
            r"
            [thresholds]
            scan_ports_per_hour = 4
            ",
        )
        .unwrap();

        assert_eq!(config.thresholds.scan_ports_per_hour, 4);
        assert_eq!(config.thresholds.scan_hosts_per_hour, 10);
        assert_eq!(config.subnets.ipv4_prefix, 24);
        assert_eq!(config.limits.max_decompressed_bytes, 4 * 1024 * 1024 * 1024);
        assert_eq!(config.scoring.volume_weight, 8);
    }

    #[test]
    fn test_full_config_is_loaded() {
        let config = AnalysisConfig::from_toml(
            r#"
            [thresholds]
            scan_ports_per_hour = 3
            scan_hosts_per_hour = 4
            bruteforce_attempts_per_hour = 5
            bruteforce_attempts_per_day = 6
            distributed_sources_per_hour = 7
            persistence_min_days = 2
            persistence_min_blocks = 8
            subnet_min_sources = 9
            min_score = 10
            scan_window_minutes = 15
            bruteforce_window_minutes = 30
            distributed_window_minutes = 45

            [integrity]
            missing_hours = 12
            out_of_order_lines = 5
            future_entries = 2

            [subnets]
            ipv4_prefix = 16
            ipv6_prefix = 48

            [ports]
            admin = [22, 3389]

            [allowlist]
            cidrs = ["192.0.2.0/24", "2001:db8::/32"]

            [scoring]
            volume_weight = 1
            ports_weight = 2
            admin_weight = 3
            persistence_weight = 4
            finding_weight = 5
            "#,
        )
        .unwrap();

        assert_eq!(config.thresholds.min_score, 10);
        assert_eq!(config.thresholds.scan_window_minutes, 15);
        assert_eq!(config.integrity.missing_hours, 12);
        assert_eq!(config.subnets.ipv4_prefix, 16);
        assert_eq!(config.ports.admin, vec![22, 3389]);
        assert_eq!(config.allowlist.cidrs.len(), 2);
        assert_eq!(config.scoring.finding_weight, 5);
    }

    #[test]
    fn test_invalid_prefix_is_rejected() {
        let error = AnalysisConfig::from_toml(
            r"
            [subnets]
            ipv4_prefix = 64
            ",
        )
        .unwrap_err();
        assert!(error.to_string().contains("ipv4_prefix"));
    }

    #[test]
    fn test_invalid_allowlist_cidr_is_rejected() {
        let error = AnalysisConfig::from_toml(
            r#"
            [allowlist]
            cidrs = ["not-a-cidr"]
            "#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid CIDR"));
    }

    #[test]
    fn test_zero_threshold_is_rejected() {
        let error = AnalysisConfig::from_toml(
            r"
            [thresholds]
            scan_ports_per_hour = 0
            ",
        )
        .unwrap_err();
        assert!(error.to_string().contains("scan_ports_per_hour"));
    }

    #[test]
    fn test_invalid_window_is_rejected() {
        let error = AnalysisConfig::from_toml(
            r"
            [thresholds]
            scan_window_minutes = 0
            ",
        )
        .unwrap_err();
        assert!(error.to_string().contains("scan_window_minutes"));

        let error = AnalysisConfig::from_toml(
            r"
            [thresholds]
            distributed_window_minutes = 10081
            ",
        )
        .unwrap_err();
        assert!(error.to_string().contains("distributed_window_minutes"));
    }

    #[test]
    fn test_integrity_zero_disables_without_validation_error() {
        let config = AnalysisConfig::from_toml(
            r"
            [integrity]
            missing_hours = 0
            out_of_order_lines = 0
            future_entries = 0
            ",
        )
        .unwrap();
        assert_eq!(config.integrity.missing_hours, 0);
    }

    #[test]
    fn test_load_without_path_uses_defaults() {
        let config = AnalysisConfig::load(None).unwrap();
        assert_eq!(config.thresholds.scan_ports_per_hour, 10);
    }
}
