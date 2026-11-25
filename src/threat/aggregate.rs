use std::collections::BTreeSet;

use chrono::{NaiveDate, NaiveDateTime};

use crate::models::{Severity, ThreatFinding, ThreatKind};

use super::window::WindowHit;

const MAX_PORTS: usize = 32;
const MAX_SOURCES: usize = 32;
const MAX_PROTOCOLS: usize = 8;

/// Accumulates non-overlapping heuristic hits for one source or target.
#[derive(Debug, Default)]
pub(crate) struct Aggregate {
    pub occurrences: u32,
    pub peak: u64,
    pub first_seen: Option<NaiveDate>,
    pub last_seen: Option<NaiveDate>,
    pub first_timestamp: Option<NaiveDateTime>,
    pub last_timestamp: Option<NaiveDateTime>,
    pub sources: BTreeSet<String>,
    pub targets: BTreeSet<String>,
    pub ports: BTreeSet<u16>,
    pub protocols: BTreeSet<String>,
}

impl Aggregate {
    /// Records one window hit, keeping the widest observed peak.
    pub(crate) fn record_hit(&mut self, hit: WindowHit) {
        self.occurrences += 1;
        self.peak = self.peak.max(hit.peak);
        let start_date = hit.start.date();
        let end_date = hit.end.date();
        self.first_seen = Some(
            self.first_seen
                .map_or(start_date, |date| date.min(start_date)),
        );
        self.last_seen = Some(self.last_seen.map_or(end_date, |date| date.max(end_date)));
        self.first_timestamp = Some(
            self.first_timestamp
                .map_or(hit.start, |timestamp| timestamp.min(hit.start)),
        );
        self.last_timestamp = Some(
            self.last_timestamp
                .map_or(hit.end, |timestamp| timestamp.max(hit.end)),
        );
    }

    pub(crate) fn record_port(&mut self, port: Option<u16>) {
        if let Some(port) = port {
            self.ports.insert(port);
        }
    }

    pub(crate) fn record_protocol(&mut self, protocol: Option<&str>) {
        if let Some(protocol) = protocol {
            self.protocols.insert(protocol.to_string());
        }
    }

    pub(crate) fn record_source(&mut self, source: &str) {
        if self.sources.len() < MAX_SOURCES {
            self.sources.insert(source.to_string());
        }
    }

    pub(crate) fn record_target(&mut self, target: Option<&str>) {
        if let Some(target) = target {
            self.targets.insert(target.to_string());
        }
    }

    /// Destination host when exactly one target was involved.
    fn unique_target(&self) -> Option<String> {
        if self.targets.len() == 1 {
            self.targets.iter().next().cloned()
        } else {
            None
        }
    }

    fn ports(&self) -> Vec<u16> {
        self.ports.iter().copied().take(MAX_PORTS).collect()
    }

    fn protocols(&self) -> Vec<String> {
        self.protocols.iter().take(MAX_PROTOCOLS).cloned().collect()
    }
}

/// Builds a source-centric finding from an aggregate.
pub(crate) fn build_source_finding(
    kind: ThreatKind,
    source_ip: &str,
    aggregate: &Aggregate,
    evidence: String,
    severity: Severity,
) -> Option<ThreatFinding> {
    let (Some(first_seen), Some(last_seen), Some(first_timestamp), Some(last_timestamp)) = (
        aggregate.first_seen,
        aggregate.last_seen,
        aggregate.first_timestamp,
        aggregate.last_timestamp,
    ) else {
        return None;
    };
    Some(ThreatFinding {
        kind,
        source_ip: Some(source_ip.to_string()),
        target_ip: aggregate.unique_target(),
        target_port: None,
        sources: Vec::new(),
        ports: aggregate.ports(),
        protocols: aggregate.protocols(),
        first_seen,
        last_seen,
        first_timestamp,
        last_timestamp,
        occurrences: aggregate.occurrences,
        peak: aggregate.peak,
        evidence,
        severity,
        technique: kind.technique().map(str::to_string),
    })
}

/// Builds a finding that describes a group rather than one source.
pub(crate) fn build_group_finding(
    kind: ThreatKind,
    target_ip: Option<&str>,
    target_port: Option<u16>,
    aggregate: &Aggregate,
    evidence: String,
    severity: Severity,
) -> Option<ThreatFinding> {
    let (Some(first_seen), Some(last_seen), Some(first_timestamp), Some(last_timestamp)) = (
        aggregate.first_seen,
        aggregate.last_seen,
        aggregate.first_timestamp,
        aggregate.last_timestamp,
    ) else {
        return None;
    };
    Some(ThreatFinding {
        kind,
        source_ip: None,
        target_ip: target_ip.map(str::to_string),
        target_port,
        sources: aggregate
            .sources
            .iter()
            .take(MAX_SOURCES)
            .cloned()
            .collect(),
        ports: aggregate.ports(),
        protocols: aggregate.protocols(),
        first_seen,
        last_seen,
        first_timestamp,
        last_timestamp,
        occurrences: aggregate.occurrences,
        peak: aggregate.peak,
        evidence,
        severity,
        technique: kind.technique().map(str::to_string),
    })
}
