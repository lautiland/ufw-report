use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;

use crate::models::{LogEntry, Severity, ThreatFinding, ThreatKind};

use super::aggregate::{build_source_finding, Aggregate};
use super::allowlist::Allowlist;
use super::config::Thresholds;

/// Detects vertical port scans and horizontal host sweeps.
///
/// A vertical scan is one source touching many destination ports within a
/// single hour. A host sweep is one source touching many destination hosts
/// within a single hour.
pub(crate) fn detect(
    entries: &[LogEntry],
    thresholds: &Thresholds,
    allowlist: &Allowlist,
) -> Vec<ThreatFinding> {
    let mut ports_by_hour: HashMap<(&str, NaiveDate, u32), HashSet<u16>> = HashMap::new();
    let mut hosts_by_hour: HashMap<(&str, NaiveDate, u32), HashSet<&str>> = HashMap::new();

    for entry in entries {
        let key = (entry.src_ip.as_str(), entry.date, entry.hour);
        if let Some(port) = entry.dst_port {
            ports_by_hour.entry(key).or_default().insert(port);
        }
        if let Some(target) = entry.dst_ip.as_deref() {
            hosts_by_hour.entry(key).or_default().insert(target);
        }
    }

    let mut vertical: HashMap<&str, Aggregate> = HashMap::new();
    for ((ip, date, _hour), ports) in ports_by_hour {
        let distinct = u32::try_from(ports.len()).unwrap_or(u32::MAX);
        if distinct >= thresholds.scan_ports_per_hour {
            vertical
                .entry(ip)
                .or_default()
                .record(date, u64::from(distinct));
        }
    }

    let mut horizontal: HashMap<&str, Aggregate> = HashMap::new();
    for ((ip, date, _hour), hosts) in hosts_by_hour {
        let distinct = u32::try_from(hosts.len()).unwrap_or(u32::MAX);
        if distinct >= thresholds.scan_hosts_per_hour {
            horizontal
                .entry(ip)
                .or_default()
                .record(date, u64::from(distinct));
        }
    }

    let mut findings = Vec::new();

    for (ip, aggregate) in vertical {
        if allowlist.contains(ip) {
            continue;
        }
        let evidence = format!(
            "{} distinct destination ports in a single hour",
            aggregate.peak
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

    for (ip, aggregate) in horizontal {
        if allowlist.contains(ip) {
            continue;
        }
        let evidence = format!(
            "{} distinct destination hosts in a single hour",
            aggregate.peak
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Direction;

    fn entry(date: NaiveDate, ip: &str, target: &str, port: u16) -> LogEntry {
        let timestamp = date
            .and_hms_opt(10, 0, 0)
            .expect("test timestamp should be valid");
        let mut entry = LogEntry::new(timestamp, ip.to_string());
        entry.dst_ip = Some(target.to_string());
        entry.dst_port = Some(port);
        entry.protocol = Some("TCP".to_string());
        entry.direction = Direction::Incoming;
        entry
    }

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 6, 28).unwrap()
    }

    #[test]
    fn test_vertical_scan_is_detected_at_threshold() {
        let entries: Vec<LogEntry> = (1..=10)
            .map(|port| entry(day(), "203.0.113.10", "192.168.1.1", port))
            .collect();

        let findings = detect(&entries, &Thresholds::default(), &Allowlist::default());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, ThreatKind::PortScan);
        assert_eq!(findings[0].source_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(findings[0].peak, 10);
    }

    #[test]
    fn test_vertical_scan_below_threshold_is_ignored() {
        let entries: Vec<LogEntry> = (1..=9)
            .map(|port| entry(day(), "203.0.113.10", "192.168.1.1", port))
            .collect();

        let findings = detect(&entries, &Thresholds::default(), &Allowlist::default());

        assert!(findings.is_empty());
    }

    #[test]
    fn test_horizontal_sweep_is_detected() {
        let entries: Vec<LogEntry> = (1..=10)
            .map(|host| entry(day(), "203.0.113.10", &format!("192.168.1.{host}"), 22))
            .collect();

        let findings = detect(&entries, &Thresholds::default(), &Allowlist::default());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, ThreatKind::HostSweep);
        assert_eq!(findings[0].peak, 10);
    }

    #[test]
    fn test_scan_aggregates_multiple_hours() {
        let entries = vec![
            entry(day(), "203.0.113.10", "192.168.1.1", 1),
            entry(day(), "203.0.113.10", "192.168.1.1", 2),
            entry(day(), "203.0.113.10", "192.168.1.1", 3),
            entry(day(), "203.0.113.10", "192.168.1.1", 4),
            entry(day(), "203.0.113.10", "192.168.1.1", 5),
            entry(day(), "203.0.113.10", "192.168.1.1", 6),
            entry(day(), "203.0.113.10", "192.168.1.1", 7),
            entry(day(), "203.0.113.10", "192.168.1.1", 8),
            entry(day(), "203.0.113.10", "192.168.1.1", 9),
            entry(day(), "203.0.113.10", "192.168.1.1", 10),
        ];

        let findings = detect(&entries, &Thresholds::default(), &Allowlist::default());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].occurrences, 1);
    }

    #[test]
    fn test_allowlisted_source_is_skipped() {
        let entries: Vec<LogEntry> = (1..=10)
            .map(|port| entry(day(), "203.0.113.10", "192.168.1.1", port))
            .collect();
        let allowlist = Allowlist::parse(&["203.0.113.0/24".to_string()]).unwrap();

        let findings = detect(&entries, &Thresholds::default(), &allowlist);

        assert!(findings.is_empty());
    }
}
