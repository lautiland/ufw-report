use chrono::{NaiveDate, NaiveDateTime};

use crate::models::{CoverageSummary, EvidenceFile, Severity, ThreatFinding, ThreatKind};

use super::config::IntegrityConfig;

/// Promotes severe coverage anomalies and unreadable inputs to findings.
///
/// The same signals remain visible in the coverage summary; these findings make
/// them impossible to miss when reading the findings section alone.
pub(crate) fn build_findings(
    coverage: &CoverageSummary,
    files: &[EvidenceFile],
    config: &IntegrityConfig,
    from: NaiveDate,
    to: NaiveDate,
) -> Vec<ThreatFinding> {
    let mut findings = Vec::new();

    if config.missing_hours > 0 && coverage.missing_hours >= config.missing_hours {
        findings.push(integrity_finding(
            ThreatKind::MissingHours,
            Severity::Low,
            from,
            to,
            format!(
                "{} of {} hours in range have no data (longest gap: {} hours)",
                coverage.missing_hours, coverage.hours_in_range, coverage.longest_gap_hours
            ),
        ));
    }

    if config.out_of_order_lines > 0
        && coverage.stats.out_of_order_lines >= config.out_of_order_lines
    {
        findings.push(integrity_finding(
            ThreatKind::OutOfOrderEntries,
            Severity::Low,
            from,
            to,
            format!(
                "{} out-of-order lines were re-sorted chronologically before analysis",
                coverage.stats.out_of_order_lines
            ),
        ));
    }

    if config.future_entries > 0 && coverage.stats.future_entries >= config.future_entries {
        findings.push(integrity_finding(
            ThreatKind::FutureDatedEntries,
            Severity::Medium,
            from,
            to,
            format!(
                "{} entries are dated after the reference date",
                coverage.stats.future_entries
            ),
        ));
    }

    for file in files {
        let Some(error) = &file.error else {
            continue;
        };
        findings.push(integrity_finding(
            ThreatKind::InputError,
            Severity::Medium,
            from,
            to,
            format!(
                "{} could not be read completely: {}",
                file.path, error.message
            ),
        ));
    }

    findings
}

fn integrity_finding(
    kind: ThreatKind,
    severity: Severity,
    from: NaiveDate,
    to: NaiveDate,
    evidence: String,
) -> ThreatFinding {
    let first_timestamp = at_start(from);
    let last_timestamp = at_end(to);

    ThreatFinding {
        kind,
        source_ip: None,
        target_ip: None,
        target_port: None,
        sources: Vec::new(),
        ports: Vec::new(),
        protocols: Vec::new(),
        first_seen: from,
        last_seen: to,
        first_timestamp,
        last_timestamp,
        occurrences: 1,
        peak: 1,
        evidence,
        severity,
        technique: kind.technique().map(str::to_string),
    }
}

fn at_start(date: NaiveDate) -> NaiveDateTime {
    date.and_hms_opt(0, 0, 0).expect("midnight is valid")
}

fn at_end(date: NaiveDate) -> NaiveDateTime {
    date.and_hms_opt(23, 59, 59).expect("end of day is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::FileErrorKind;
    use crate::models::ParseStats;

    fn date() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 6, 28).unwrap()
    }

    fn coverage() -> CoverageSummary {
        CoverageSummary {
            stats: ParseStats::default(),
            hours_in_range: 72,
            hours_with_data: 2,
            missing_hours: 70,
            longest_gap_hours: 24,
            coverage_pct: 2.78,
        }
    }

    fn file() -> EvidenceFile {
        EvidenceFile {
            path: "/var/log/ufw.log.2.gz".to_string(),
            canonical_path: "/var/log/ufw.log.2.gz".to_string(),
            sha256: String::new(),
            size_bytes: 10,
            decompressed_bytes: 0,
            modified_at: None,
            compressed: true,
            from_cache: false,
            parse_stats: ParseStats::default(),
            error: Some(crate::models::FileError::new(
                FileErrorKind::CorruptGzip,
                "bad gzip header",
            )),
        }
    }

    #[test]
    fn test_missing_hours_becomes_a_finding() {
        let findings = build_findings(
            &coverage(),
            &[],
            &IntegrityConfig::default(),
            date(),
            date(),
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, ThreatKind::MissingHours);
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0].evidence.contains("70 of 72"));
        assert!(findings[0].technique.is_none());
    }

    #[test]
    fn test_integrity_threshold_zero_disables_the_check() {
        let config = IntegrityConfig {
            missing_hours: 0,
            ..IntegrityConfig::default()
        };

        let findings = build_findings(&coverage(), &[], &config, date(), date());

        assert!(findings.is_empty());
    }

    #[test]
    fn test_parser_counters_are_promoted() {
        let mut coverage = coverage();
        coverage.stats.out_of_order_lines = 12;
        coverage.stats.future_entries = 2;

        let findings = build_findings(&coverage, &[], &IntegrityConfig::default(), date(), date());

        assert!(findings
            .iter()
            .any(|finding| finding.kind == ThreatKind::OutOfOrderEntries));
        assert!(findings
            .iter()
            .any(|finding| finding.kind == ThreatKind::FutureDatedEntries));
    }

    #[test]
    fn test_unreadable_input_becomes_a_finding() {
        let config = IntegrityConfig {
            missing_hours: 0,
            ..IntegrityConfig::default()
        };

        let findings = build_findings(&coverage(), &[file()], &config, date(), date());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, ThreatKind::InputError);
        assert!(findings[0].evidence.contains("ufw.log.2.gz"));
        assert!(findings[0].evidence.contains("bad gzip header"));
    }
}
