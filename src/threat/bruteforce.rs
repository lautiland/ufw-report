use std::collections::{HashMap, HashSet};

use chrono::{NaiveDate, NaiveDateTime};

use crate::models::{LogEntry, Severity, ThreatFinding, ThreatKind};

use super::aggregate::{build_group_finding, build_source_finding, Aggregate};
use super::allowlist::Allowlist;
use super::config::Thresholds;
use super::window::{count_hits, distinct_hits, window_from_minutes, WindowHit};

#[derive(Debug, Default)]
struct SourceAccumulator<'a> {
    times: Vec<NaiveDateTime>,
    entries: Vec<&'a LogEntry>,
    by_day: HashMap<NaiveDate, Vec<NaiveDateTime>>,
}

/// Detects bursts against administrative ports over the configured window and
/// retains the daily threshold from earlier releases.
pub(crate) fn detect_bruteforce(
    entries: &[LogEntry],
    thresholds: &Thresholds,
    admin_ports: &HashSet<u16>,
    allowlist: &Allowlist,
) -> Vec<ThreatFinding> {
    let mut by_source: HashMap<&str, SourceAccumulator> = HashMap::new();

    for entry in entries {
        let Some(port) = entry.dst_port else {
            continue;
        };
        if !admin_ports.contains(&port) {
            continue;
        }
        let accumulator = by_source.entry(entry.src_ip.as_str()).or_default();
        accumulator.times.push(entry.timestamp);
        accumulator.entries.push(entry);
        accumulator
            .by_day
            .entry(entry.date)
            .or_default()
            .push(entry.timestamp);
    }

    let window = window_from_minutes(thresholds.bruteforce_window_minutes);
    let mut findings = Vec::new();

    for (ip, source) in by_source {
        if allowlist.contains(ip) {
            continue;
        }

        let mut aggregate = Aggregate::default();
        let window_hits = count_hits(
            source.times.clone(),
            window,
            thresholds.bruteforce_attempts_per_hour,
        );
        let mut window_peak = 0;
        let mut window_days = HashSet::new();
        for hit in &window_hits {
            window_days.insert(hit.start.date());
            window_peak = window_peak.max(hit.peak);
        }

        for hit in window_hits {
            record_evidence(&mut aggregate, &source.entries, hit.start, hit.end);
            aggregate.record_hit(hit);
        }

        let mut daily_peak = 0;
        let mut daily_only_days: Vec<(NaiveDate, Vec<NaiveDateTime>)> = source
            .by_day
            .into_iter()
            .filter(|(date, times)| {
                !window_days.contains(date)
                    && u64::try_from(times.len()).unwrap_or(u64::MAX)
                        >= thresholds.bruteforce_attempts_per_day
            })
            .collect();
        daily_only_days.sort_by_key(|(date, _)| *date);

        for (date, mut times) in daily_only_days {
            times.sort_unstable();
            let count = u64::try_from(times.len()).unwrap_or(u64::MAX);
            daily_peak = daily_peak.max(count);
            let start = times.first().copied().unwrap_or_else(|| day_start(date));
            let end = times.last().copied().unwrap_or_else(|| day_end(date));
            record_evidence(&mut aggregate, &source.entries, start, end);
            aggregate.record_hit(WindowHit::new(start, end, count));
        }

        if aggregate.occurrences == 0 {
            continue;
        }

        let evidence = if daily_peak > window_peak {
            format!("{daily_peak} attempts against administrative ports in one day")
        } else {
            format!(
                "{} attempts against administrative ports in a {}-minute window",
                window_peak, thresholds.bruteforce_window_minutes
            )
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

fn day_start(date: NaiveDate) -> NaiveDateTime {
    date.and_hms_opt(0, 0, 0).expect("midnight is valid")
}

fn day_end(date: NaiveDate) -> NaiveDateTime {
    date.and_hms_opt(23, 59, 59).expect("end of day is valid")
}

fn record_evidence(
    aggregate: &mut Aggregate,
    entries: &[&LogEntry],
    start: NaiveDateTime,
    end: NaiveDateTime,
) {
    for entry in entries
        .iter()
        .filter(|entry| entry.timestamp >= start && entry.timestamp <= end)
    {
        aggregate.record_port(entry.dst_port);
        aggregate.record_target(entry.dst_ip.as_deref());
        aggregate.record_protocol(entry.protocol.as_deref());
    }
}

/// Detects many distinct sources hitting the same target and port within the
/// configured window.
pub(crate) fn detect_distributed(
    entries: &[LogEntry],
    thresholds: &Thresholds,
    allowlist: &Allowlist,
) -> Vec<ThreatFinding> {
    let items: Vec<((&str, u16), NaiveDateTime, &str)> = entries
        .iter()
        .filter_map(|entry| {
            let target = entry.dst_ip.as_deref()?;
            let port = entry.dst_port?;
            if allowlist.contains(&entry.src_ip) {
                return None;
            }
            Some(((target, port), entry.timestamp, entry.src_ip.as_str()))
        })
        .collect();

    let hits = distinct_hits(
        items,
        window_from_minutes(thresholds.distributed_window_minutes),
        u64::from(thresholds.distributed_sources_per_hour),
    );

    let mut findings = Vec::new();
    for ((target, port), target_hits) in hits {
        let mut aggregate = Aggregate::default();
        aggregate.record_port(Some(port));
        for hit in target_hits {
            for entry in entries.iter().filter(|entry| {
                entry.dst_ip.as_deref() == Some(target)
                    && entry.dst_port == Some(port)
                    && entry.timestamp >= hit.start
                    && entry.timestamp <= hit.end
                    && !allowlist.contains(&entry.src_ip)
            }) {
                aggregate.record_source(&entry.src_ip);
                aggregate.record_protocol(entry.protocol.as_deref());
            }
            aggregate.record_hit(hit);
        }

        if let Some(finding) = build_group_finding(
            ThreatKind::DistributedBruteForce,
            Some(target),
            Some(port),
            &aggregate,
            format!(
                "{} distinct sources against port {} in a {}-minute window",
                aggregate.peak, port, thresholds.distributed_window_minutes
            ),
            Severity::Critical,
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
    use chrono::Duration;

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
        entry.direction = Direction::Incoming;
        entry
    }

    fn admin_ports() -> HashSet<u16> {
        HashSet::from([22, 3389])
    }

    #[test]
    fn test_hourly_bruteforce_is_detected_at_threshold() {
        let entries: Vec<LogEntry> = (0..20)
            .map(|_| entry(at(10, 0, 0), "203.0.113.10", "192.168.1.1", 22))
            .collect();

        let findings = detect_bruteforce(
            &entries,
            &Thresholds::default(),
            &admin_ports(),
            &Allowlist::default(),
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, ThreatKind::BruteForce);
        assert_eq!(findings[0].target_ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(findings[0].peak, 20);
        assert_eq!(findings[0].occurrences, 1);
        assert_eq!(findings[0].technique.as_deref(), Some("T1110"));
    }

    #[test]
    fn test_bruteforce_window_crosses_an_hour_boundary() {
        let base = at(10, 59, 20);
        let entries: Vec<LogEntry> = (0..20)
            .map(|offset| {
                entry(
                    base + Duration::seconds(offset * 5),
                    "203.0.113.10",
                    "192.168.1.1",
                    22,
                )
            })
            .collect();

        let findings = detect_bruteforce(
            &entries,
            &Thresholds::default(),
            &admin_ports(),
            &Allowlist::default(),
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].first_timestamp, at(10, 59, 20));
        assert_eq!(findings[0].last_timestamp, at(11, 0, 55));
    }

    #[test]
    fn test_narrow_bruteforce_window_suppresses_the_burst() {
        let base = at(10, 59, 20);
        let entries: Vec<LogEntry> = (0..20)
            .map(|offset| {
                entry(
                    base + Duration::seconds(offset * 5),
                    "203.0.113.10",
                    "192.168.1.1",
                    22,
                )
            })
            .collect();
        let config = Thresholds {
            bruteforce_window_minutes: 1,
            bruteforce_attempts_per_day: 1000,
            ..Thresholds::default()
        };

        let findings = detect_bruteforce(&entries, &config, &admin_ports(), &Allowlist::default());

        assert!(findings.is_empty());
    }

    #[test]
    fn test_daily_bruteforce_is_detected_below_hourly_threshold() {
        let mut entries = Vec::new();
        for hour in 0..3 {
            for _ in 0..if hour == 2 { 16 } else { 17 } {
                entries.push(entry(at(hour, 0, 0), "203.0.113.10", "192.168.1.1", 22));
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
            .map(|_| entry(at(10, 0, 0), "203.0.113.10", "192.168.1.1", 80))
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
            .map(|_| entry(at(10, 0, 0), "203.0.113.10", "192.168.1.1", 22))
            .collect();
        let allowlist = Allowlist::parse(&["203.0.113.0/24".to_string()]).unwrap();

        let findings =
            detect_bruteforce(&entries, &Thresholds::default(), &admin_ports(), &allowlist);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_distributed_bruteforce_is_detected() {
        let entries: Vec<LogEntry> = (0..20)
            .map(|index| {
                entry(
                    at(10, 0, 0),
                    &format!("203.0.113.{index}"),
                    "192.168.1.1",
                    22,
                )
            })
            .collect();

        let findings = detect_distributed(&entries, &Thresholds::default(), &Allowlist::default());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, ThreatKind::DistributedBruteForce);
        assert_eq!(findings[0].target_ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(findings[0].target_port, Some(22));
        assert_eq!(findings[0].peak, 20);
        assert_eq!(findings[0].sources.len(), 20);
        assert_eq!(findings[0].technique.as_deref(), Some("T1110"));
    }

    #[test]
    fn test_distributed_below_threshold_is_ignored() {
        let entries: Vec<LogEntry> = (0..19)
            .map(|index| {
                entry(
                    at(10, 0, 0),
                    &format!("203.0.113.{index}"),
                    "192.168.1.1",
                    22,
                )
            })
            .collect();

        let findings = detect_distributed(&entries, &Thresholds::default(), &Allowlist::default());

        assert!(findings.is_empty());
    }

    #[test]
    fn test_distributed_skips_allowlisted_sources() {
        let entries: Vec<LogEntry> = (0..20)
            .map(|index| {
                entry(
                    at(10, 0, 0),
                    &format!("203.0.113.{index}"),
                    "192.168.1.1",
                    22,
                )
            })
            .collect();
        let allowlist = Allowlist::parse(&["203.0.113.0/24".to_string()]).unwrap();

        let findings = detect_distributed(&entries, &Thresholds::default(), &allowlist);

        assert!(findings.is_empty());
    }
}
