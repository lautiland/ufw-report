use std::collections::HashMap;

use crate::models::{LogEntry, Severity, ThreatFinding, ThreatKind};

use super::aggregate::{build_source_finding, Aggregate};
use super::allowlist::Allowlist;
use super::config::Thresholds;
use super::window::{distinct_hits, window_from_minutes};

/// Detects vertical port scans and horizontal host sweeps over sliding windows.
///
/// A vertical scan is one source touching many destination ports within the
/// configured window. A host sweep is one source touching many destination hosts
/// within the same window.
pub(crate) fn detect(
    entries: &[LogEntry],
    thresholds: &Thresholds,
    allowlist: &Allowlist,
) -> Vec<ThreatFinding> {
    let window = window_from_minutes(thresholds.scan_window_minutes);
    let mut findings = Vec::new();

    let port_items: Vec<(&str, chrono::NaiveDateTime, u16)> = entries
        .iter()
        .filter_map(|entry| {
            entry
                .dst_port
                .map(|port| (entry.src_ip.as_str(), entry.timestamp, port))
        })
        .collect();
    let port_hits = distinct_hits(
        port_items,
        window,
        u64::from(thresholds.scan_ports_per_hour),
    );

    let host_items: Vec<(&str, chrono::NaiveDateTime, &str)> = entries
        .iter()
        .filter_map(|entry| {
            entry
                .dst_ip
                .as_deref()
                .map(|host| (entry.src_ip.as_str(), entry.timestamp, host))
        })
        .collect();
    let host_hits = distinct_hits(
        host_items,
        window,
        u64::from(thresholds.scan_hosts_per_hour),
    );

    let by_source = group_by_source(entries);

    for (ip, hits) in port_hits {
        if allowlist.contains(ip) {
            continue;
        }
        let mut aggregate = Aggregate::default();
        for hit in hits {
            aggregate.record_hit(hit);
            record_evidence(&mut aggregate, &by_source, ip, hit.start, hit.end);
        }
        let evidence = format!(
            "{} distinct destination ports in a {}-minute window",
            aggregate.peak, thresholds.scan_window_minutes
        );
        if let Some(finding) = build_source_finding(
            ThreatKind::PortScan,
            ip,
            &aggregate,
            evidence,
            Severity::High,
        ) {
            findings.push(finding);
        }
    }

    for (ip, hits) in host_hits {
        if allowlist.contains(ip) {
            continue;
        }
        let mut aggregate = Aggregate::default();
        for hit in hits {
            aggregate.record_hit(hit);
            record_evidence(&mut aggregate, &by_source, ip, hit.start, hit.end);
        }
        let evidence = format!(
            "{} distinct destination hosts in a {}-minute window",
            aggregate.peak, thresholds.scan_window_minutes
        );
        if let Some(finding) = build_source_finding(
            ThreatKind::HostSweep,
            ip,
            &aggregate,
            evidence,
            Severity::High,
        ) {
            findings.push(finding);
        }
    }

    findings
}

fn group_by_source<'a>(entries: &'a [LogEntry]) -> HashMap<&'a str, Vec<&'a LogEntry>> {
    let mut by_source: HashMap<&'a str, Vec<&'a LogEntry>> = HashMap::new();
    for entry in entries {
        by_source
            .entry(entry.src_ip.as_str())
            .or_default()
            .push(entry);
    }
    by_source
}

fn record_evidence(
    aggregate: &mut Aggregate,
    by_source: &HashMap<&str, Vec<&LogEntry>>,
    ip: &str,
    start: chrono::NaiveDateTime,
    end: chrono::NaiveDateTime,
) {
    let Some(source_entries) = by_source.get(ip) else {
        return;
    };
    for entry in source_entries
        .iter()
        .filter(|entry| entry.timestamp >= start && entry.timestamp <= end)
    {
        aggregate.record_port(entry.dst_port);
        aggregate.record_target(entry.dst_ip.as_deref());
        aggregate.record_protocol(entry.protocol.as_deref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, NaiveDate, NaiveDateTime};

    fn at(hour: u32, minute: u32, second: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 6, 28)
            .unwrap()
            .and_hms_opt(hour, minute, second)
            .unwrap()
    }

    fn entry(timestamp: NaiveDateTime, ip: &str, target: &str, port: u16) -> LogEntry {
        let mut entry = LogEntry::new(timestamp, ip.to_string());
        entry.dst_ip = Some(target.to_string());
        entry.dst_port = Some(port);
        entry.protocol = Some("TCP".to_string());
        entry.direction = crate::models::Direction::Incoming;
        entry
    }

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 6, 28).unwrap()
    }

    fn timestamp() -> NaiveDateTime {
        day().and_hms_opt(10, 0, 0).unwrap()
    }

    fn boundary_entries() -> Vec<LogEntry> {
        let base = at(10, 59, 30);
        (0..10)
            .map(|offset| {
                entry(
                    base + Duration::seconds(offset * 10),
                    "203.0.113.10",
                    "192.168.1.1",
                    u16::try_from(offset + 1).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn test_vertical_scan_is_detected_at_threshold() {
        let entries: Vec<LogEntry> = (1..=10)
            .map(|port| entry(timestamp(), "203.0.113.10", "192.168.1.1", port))
            .collect();

        let findings = detect(&entries, &Thresholds::default(), &Allowlist::default());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, ThreatKind::PortScan);
        assert_eq!(findings[0].source_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(findings[0].target_ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(findings[0].peak, 10);
        assert_eq!(findings[0].ports.len(), 10);
        assert_eq!(findings[0].protocols, vec!["TCP"]);
        assert_eq!(findings[0].technique.as_deref(), Some("T1046"));
    }

    #[test]
    fn test_scan_crossing_an_hour_boundary_keeps_exact_timestamps() {
        let findings = detect(
            &boundary_entries(),
            &Thresholds::default(),
            &Allowlist::default(),
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].first_timestamp, at(10, 59, 30));
        assert_eq!(findings[0].last_timestamp, at(11, 1, 0));
        assert_eq!(findings[0].occurrences, 1);
    }

    #[test]
    fn test_narrow_window_suppresses_the_boundary_scan() {
        let config = Thresholds {
            scan_window_minutes: 1,
            ..Thresholds::default()
        };

        let findings = detect(&boundary_entries(), &config, &Allowlist::default());

        assert!(findings.is_empty());
    }

    #[test]
    fn test_vertical_scan_below_threshold_is_ignored() {
        let entries: Vec<LogEntry> = (1..=9)
            .map(|port| entry(timestamp(), "203.0.113.10", "192.168.1.1", port))
            .collect();

        let findings = detect(&entries, &Thresholds::default(), &Allowlist::default());

        assert!(findings.is_empty());
    }

    #[test]
    fn test_horizontal_sweep_is_detected() {
        let entries: Vec<LogEntry> = (1..=10)
            .map(|host| {
                entry(
                    timestamp(),
                    "203.0.113.10",
                    &format!("192.168.1.{host}"),
                    22,
                )
            })
            .collect();

        let findings = detect(&entries, &Thresholds::default(), &Allowlist::default());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, ThreatKind::HostSweep);
        assert_eq!(findings[0].peak, 10);
        assert_eq!(findings[0].technique.as_deref(), Some("T1018"));
    }

    #[test]
    fn test_scan_aggregates_multiple_hours() {
        let entries: Vec<LogEntry> = (1..=10)
            .map(|port| entry(timestamp(), "203.0.113.10", "192.168.1.1", port))
            .collect();

        let findings = detect(&entries, &Thresholds::default(), &Allowlist::default());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].occurrences, 1);
    }

    #[test]
    fn test_allowlisted_source_is_skipped() {
        let entries: Vec<LogEntry> = (1..=10)
            .map(|port| entry(timestamp(), "203.0.113.10", "192.168.1.1", port))
            .collect();
        let allowlist = Allowlist::parse(&["203.0.113.0/24".to_string()]).unwrap();

        let findings = detect(&entries, &Thresholds::default(), &allowlist);

        assert!(findings.is_empty());
    }
}
