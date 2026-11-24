use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;

use crate::models::{LogEntry, Severity, ThreatFinding, ThreatKind};

use super::aggregate::{build_source_finding, Aggregate};
use super::allowlist::Allowlist;
use super::config::Thresholds;

#[derive(Debug, Default)]
struct SourceAccumulator {
    hourly_hits: HashSet<(NaiveDate, u32)>,
    daily_hits: HashSet<NaiveDate>,
    peak_hour: u64,
    peak_day: u64,
}

/// Detects bursts against administrative ports, both hourly and daily.
pub(crate) fn detect_bruteforce(
    entries: &[LogEntry],
    thresholds: &Thresholds,
    admin_ports: &HashSet<u16>,
    allowlist: &Allowlist,
) -> Vec<ThreatFinding> {
    let mut hourly: HashMap<(&str, NaiveDate, u32), u64> = HashMap::new();
    let mut daily: HashMap<(&str, NaiveDate), u64> = HashMap::new();

    for entry in entries {
        let Some(port) = entry.dst_port else {
            continue;
        };
        if !admin_ports.contains(&port) {
            continue;
        }
        *hourly
            .entry((entry.src_ip.as_str(), entry.date, entry.hour))
            .or_insert(0) += 1;
        *daily
            .entry((entry.src_ip.as_str(), entry.date))
            .or_insert(0) += 1;
    }

    let mut by_source: HashMap<&str, SourceAccumulator> = HashMap::new();

    for ((ip, date, hour), count) in hourly {
        if count >= thresholds.bruteforce_attempts_per_hour {
            let accumulator = by_source.entry(ip).or_default();
            accumulator.hourly_hits.insert((date, hour));
            accumulator.peak_hour = accumulator.peak_hour.max(count);
        }
    }

    for ((ip, date), count) in daily {
        if count >= thresholds.bruteforce_attempts_per_day {
            let accumulator = by_source.entry(ip).or_default();
            accumulator.daily_hits.insert(date);
            accumulator.peak_day = accumulator.peak_day.max(count);
        }
    }

    let mut findings = Vec::new();

    for (ip, accumulator) in by_source {
        if allowlist.contains(ip) {
            continue;
        }

        let daily_only = accumulator
            .daily_hits
            .iter()
            .filter(|day| {
                !accumulator
                    .hourly_hits
                    .iter()
                    .any(|(hour_day, _hour)| hour_day == *day)
            })
            .count();
        let occurrences =
            u32::try_from(accumulator.hourly_hits.len() + daily_only).unwrap_or(u32::MAX);

        let mut dates: Vec<NaiveDate> = accumulator
            .hourly_hits
            .iter()
            .map(|(date, _hour)| *date)
            .chain(accumulator.daily_hits.iter().copied())
            .collect();
        dates.sort_unstable();
        let Some(first_seen) = dates.first().copied() else {
            continue;
        };
        let last_seen = dates.last().copied().unwrap_or(first_seen);

        let peak = accumulator.peak_hour.max(accumulator.peak_day);
        let evidence = if accumulator.peak_hour >= thresholds.bruteforce_attempts_per_hour {
            format!(
                "{} attempts against administrative ports in one hour",
                accumulator.peak_hour
            )
        } else {
            format!(
                "{} attempts against administrative ports in one day",
                accumulator.peak_day
            )
        };

        let aggregate = Aggregate {
            occurrences,
            peak,
            first_seen: Some(first_seen),
            last_seen: Some(last_seen),
        };
        if let Some(finding) = build_source_finding(
            ThreatKind::BruteForce,
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

/// Detects many distinct sources hitting the same target and port in one hour.
pub(crate) fn detect_distributed(
    entries: &[LogEntry],
    thresholds: &Thresholds,
    allowlist: &Allowlist,
) -> Vec<ThreatFinding> {
    let mut buckets: HashMap<(&str, u16, NaiveDate, u32), HashSet<&str>> = HashMap::new();

    for entry in entries {
        let (Some(target), Some(port)) = (entry.dst_ip.as_deref(), entry.dst_port) else {
            continue;
        };
        if allowlist.contains(&entry.src_ip) {
            continue;
        }
        buckets
            .entry((target, port, entry.date, entry.hour))
            .or_default()
            .insert(entry.src_ip.as_str());
    }

    let mut by_target: HashMap<(&str, u16), Aggregate> = HashMap::new();
    for ((target, port, date, _hour), sources) in buckets {
        let distinct = u32::try_from(sources.len()).unwrap_or(u32::MAX);
        if distinct >= thresholds.distributed_sources_per_hour {
            by_target
                .entry((target, port))
                .or_default()
                .record(date, u64::from(distinct));
        }
    }

    let mut findings = Vec::new();
    for ((target, port), aggregate) in by_target {
        let (Some(first_seen), Some(last_seen)) = (aggregate.first_seen, aggregate.last_seen)
        else {
            continue;
        };
        findings.push(ThreatFinding {
            kind: ThreatKind::DistributedBruteForce,
            source_ip: None,
            target_ip: Some(target.to_string()),
            target_port: Some(port),
            first_seen,
            last_seen,
            occurrences: aggregate.occurrences,
            peak: aggregate.peak,
            evidence: format!(
                "{} distinct sources against port {} in one hour",
                aggregate.peak, port
            ),
            severity: Severity::Critical,
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Direction;

    fn entry(date: NaiveDate, hour: u32, ip: &str, target: &str, port: u16) -> LogEntry {
        let timestamp = date
            .and_hms_opt(hour, 0, 0)
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

    fn admin_ports() -> HashSet<u16> {
        HashSet::from([22, 3389])
    }

    #[test]
    fn test_hourly_bruteforce_is_detected_at_threshold() {
        let entries: Vec<LogEntry> = (0..20)
            .map(|_| entry(day(), 10, "203.0.113.10", "192.168.1.1", 22))
            .collect();

        let findings = detect_bruteforce(
            &entries,
            &Thresholds::default(),
            &admin_ports(),
            &Allowlist::default(),
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, ThreatKind::BruteForce);
        assert_eq!(findings[0].peak, 20);
        assert_eq!(findings[0].occurrences, 1);
    }

    #[test]
    fn test_daily_bruteforce_is_detected_below_hourly_threshold() {
        let mut entries = Vec::new();
        for hour in 0..3 {
            for _ in 0..if hour == 2 { 16 } else { 17 } {
                entries.push(entry(day(), hour, "203.0.113.10", "192.168.1.1", 22));
            }
        }

        let findings = detect_bruteforce(
            &entries,
            &Thresholds::default(),
            &admin_ports(),
            &Allowlist::default(),
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].occurrences, 1);
        assert_eq!(findings[0].peak, 50);
        assert!(findings[0].evidence.contains("one day"));
    }

    #[test]
    fn test_non_admin_ports_are_ignored() {
        let entries: Vec<LogEntry> = (0..30)
            .map(|_| entry(day(), 10, "203.0.113.10", "192.168.1.1", 80))
            .collect();

        let findings = detect_bruteforce(
            &entries,
            &Thresholds::default(),
            &admin_ports(),
            &Allowlist::default(),
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn test_allowlisted_source_is_skipped() {
        let entries: Vec<LogEntry> = (0..30)
            .map(|_| entry(day(), 10, "203.0.113.10", "192.168.1.1", 22))
            .collect();
        let allowlist = Allowlist::parse(&["203.0.113.0/24".to_string()]).unwrap();

        let findings =
            detect_bruteforce(&entries, &Thresholds::default(), &admin_ports(), &allowlist);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_distributed_bruteforce_is_detected() {
        let entries: Vec<LogEntry> = (0..20)
            .map(|index| entry(day(), 10, &format!("203.0.113.{index}"), "192.168.1.1", 22))
            .collect();

        let findings = detect_distributed(&entries, &Thresholds::default(), &Allowlist::default());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, ThreatKind::DistributedBruteForce);
        assert_eq!(findings[0].target_ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(findings[0].target_port, Some(22));
        assert_eq!(findings[0].peak, 20);
    }

    #[test]
    fn test_distributed_below_threshold_is_ignored() {
        let entries: Vec<LogEntry> = (0..19)
            .map(|index| entry(day(), 10, &format!("203.0.113.{index}"), "192.168.1.1", 22))
            .collect();

        let findings = detect_distributed(&entries, &Thresholds::default(), &Allowlist::default());

        assert!(findings.is_empty());
    }

    #[test]
    fn test_distributed_skips_allowlisted_sources() {
        let entries: Vec<LogEntry> = (0..20)
            .map(|index| entry(day(), 10, &format!("203.0.113.{index}"), "192.168.1.1", 22))
            .collect();
        let allowlist = Allowlist::parse(&["203.0.113.0/24".to_string()]).unwrap();

        let findings = detect_distributed(&entries, &Thresholds::default(), &allowlist);

        assert!(findings.is_empty());
    }
}
