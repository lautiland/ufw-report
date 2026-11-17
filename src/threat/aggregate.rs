use chrono::NaiveDate;

use crate::models::{Severity, ThreatFinding, ThreatKind};

/// Accumulates heuristic hits for one source or target.
#[derive(Debug, Default)]
pub(crate) struct Aggregate {
    pub occurrences: u32,
    pub peak: u64,
    pub first_seen: Option<NaiveDate>,
    pub last_seen: Option<NaiveDate>,
}

impl Aggregate {
    pub(crate) fn record(&mut self, date: NaiveDate, value: u64) {
        self.occurrences += 1;
        self.peak = self.peak.max(value);
        self.first_seen = Some(self.first_seen.map_or(date, |current| current.min(date)));
        self.last_seen = Some(self.last_seen.map_or(date, |current| current.max(date)));
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
    let (Some(first_seen), Some(last_seen)) = (aggregate.first_seen, aggregate.last_seen) else {
        return None;
    };
    Some(ThreatFinding {
        kind,
        source_ip: Some(source_ip.to_string()),
        target_ip: None,
        target_port: None,
        first_seen,
        last_seen,
        occurrences: aggregate.occurrences,
        peak: aggregate.peak,
        evidence,
        severity,
    })
}
