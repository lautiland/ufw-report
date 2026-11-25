use chrono::{NaiveDate, NaiveDateTime};
use serde::{Deserialize, Serialize};

use super::{CustodyManifest, ParseStats, PortEntry};

/// Threat categories produced by the offline heuristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ThreatKind {
    PortScan,
    HostSweep,
    BruteForce,
    DistributedBruteForce,
    PersistentSource,
    MissingHours,
    OutOfOrderEntries,
    FutureDatedEntries,
    InputError,
}

impl ThreatKind {
    pub const ALL: [Self; 9] = [
        Self::PortScan,
        Self::HostSweep,
        Self::BruteForce,
        Self::DistributedBruteForce,
        Self::PersistentSource,
        Self::MissingHours,
        Self::OutOfOrderEntries,
        Self::FutureDatedEntries,
        Self::InputError,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PortScan => "Port scan",
            Self::HostSweep => "Host sweep",
            Self::BruteForce => "Brute force",
            Self::DistributedBruteForce => "Distributed brute force",
            Self::PersistentSource => "Persistent source",
            Self::MissingHours => "Missing log hours",
            Self::OutOfOrderEntries => "Out-of-order log lines",
            Self::FutureDatedEntries => "Future-dated log entries",
            Self::InputError => "Input error",
        }
    }

    #[must_use]
    pub const fn short_label(self) -> &'static str {
        match self {
            Self::PortScan => "scan",
            Self::HostSweep => "sweep",
            Self::BruteForce => "brute",
            Self::DistributedBruteForce => "dist",
            Self::PersistentSource => "persist",
            Self::MissingHours => "gap",
            Self::OutOfOrderEntries => "order",
            Self::FutureDatedEntries => "future",
            Self::InputError => "input",
        }
    }

    /// MITRE ATT&CK technique that cleanly describes this finding.
    ///
    /// Persistence, coverage, and input findings return `None` on purpose: no
    /// defensible identifier exists for them.
    #[must_use]
    pub const fn technique(self) -> Option<&'static str> {
        match self {
            Self::PortScan => Some("T1046"),
            Self::HostSweep => Some("T1018"),
            Self::BruteForce | Self::DistributedBruteForce => Some("T1110"),
            Self::PersistentSource
            | Self::MissingHours
            | Self::OutOfOrderEntries
            | Self::FutureDatedEntries
            | Self::InputError => None,
        }
    }

    /// `true` for findings about evidence quality rather than observed attacks.
    #[must_use]
    pub const fn is_integrity(self) -> bool {
        matches!(
            self,
            Self::MissingHours
                | Self::OutOfOrderEntries
                | Self::FutureDatedEntries
                | Self::InputError
        )
    }
}

/// Risk bands derived from the 0-100 score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub const fn from_score(score: u8) -> Self {
        match score {
            0..=24 => Self::Low,
            25..=49 => Self::Medium,
            50..=74 => Self::High,
            _ => Self::Critical,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

/// Aggregated view of one source IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProfile {
    pub ip: String,
    pub total_blocks: u64,
    pub first_seen: NaiveDate,
    pub last_seen: NaiveDate,
    pub active_days: u32,
    pub distinct_dst_ports: u32,
    pub distinct_dst_ips: u32,
    pub admin_port_hits: u64,
    pub top_ports: Vec<PortEntry>,
    pub top_protocols: Vec<(String, u64)>,
    pub findings: Vec<ThreatKind>,
    pub risk_score: u8,
    pub severity: Severity,
}

/// A single heuristic hit, aggregated by source/target/kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFinding {
    pub kind: ThreatKind,
    pub source_ip: Option<String>,
    pub target_ip: Option<String>,
    pub target_port: Option<u16>,
    /// Distinct sources involved, for findings that describe a group.
    pub sources: Vec<String>,
    /// Distinct destination ports involved.
    pub ports: Vec<u16>,
    /// Distinct protocols involved.
    pub protocols: Vec<String>,
    pub first_seen: NaiveDate,
    pub last_seen: NaiveDate,
    /// Exact start of the evidence, to the second.
    pub first_timestamp: NaiveDateTime,
    /// Exact end of the evidence, to the second.
    pub last_timestamp: NaiveDateTime,
    pub occurrences: u32,
    pub peak: u64,
    pub evidence: String,
    pub severity: Severity,
    /// Defensible MITRE ATT&CK technique, when one applies.
    pub technique: Option<String>,
}

/// Aggregation of every source inside one IPv4 /24 or IPv6 /64 prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetAggregate {
    pub prefix: String,
    pub total_blocks: u64,
    pub distinct_sources: u32,
    pub distinct_ports: u32,
    pub top_ports: Vec<PortEntry>,
    pub first_seen: NaiveDate,
    pub last_seen: NaiveDate,
}

/// Log quality and hourly coverage for the requested range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub stats: ParseStats,
    pub hours_in_range: u32,
    pub hours_with_data: u32,
    pub missing_hours: u32,
    pub longest_gap_hours: u32,
    pub coverage_pct: f64,
}

/// High-level counters used by the TUI header and the Markdown export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSummary {
    pub total_sources: u32,
    pub ranked_sources: u32,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub total_findings: usize,
    pub top_source: Option<String>,
    pub top_score: u8,
}

/// Complete read-only threat analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub profiles: Vec<SourceProfile>,
    pub findings: Vec<ThreatFinding>,
    pub subnets: Vec<SubnetAggregate>,
    pub coverage: CoverageSummary,
    pub summary: ThreatSummary,
    pub custody: CustodyManifest,
}

impl ThreatReport {
    /// Empty report used when the caller needs a placeholder.
    #[must_use]
    pub fn empty(from: NaiveDate, to: NaiveDate) -> Self {
        Self {
            from,
            to,
            profiles: Vec::new(),
            findings: Vec::new(),
            subnets: Vec::new(),
            coverage: CoverageSummary {
                stats: ParseStats::default(),
                hours_in_range: 0,
                hours_with_data: 0,
                missing_hours: 0,
                longest_gap_hours: 0,
                coverage_pct: 0.0,
            },
            summary: ThreatSummary {
                total_sources: 0,
                ranked_sources: 0,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                total_findings: 0,
                top_source: None,
                top_score: 0,
            },
            custody: CustodyManifest::empty(),
        }
    }
}
