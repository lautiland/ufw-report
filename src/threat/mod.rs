pub mod config;

pub(crate) mod aggregate;
pub(crate) mod allowlist;
pub(crate) mod bruteforce;
pub(crate) mod coverage;
pub(crate) mod offenders;
pub(crate) mod scan;
pub(crate) mod scoring;
pub(crate) mod subnets;
pub(crate) mod util;

use std::collections::HashMap;

use chrono::NaiveDate;

use crate::models::{
    LogEntry, ParseStats, Severity, SourceProfile, ThreatFinding, ThreatKind, ThreatReport,
    ThreatSummary,
};

use self::allowlist::Allowlist;
use self::config::{AnalysisConfig, Thresholds};

/// Runs the read-only analysis pipeline.
///
/// # Errors
///
/// Returns an error when the allowlist contains an invalid CIDR.
pub fn analyze(
    entries: &[LogEntry],
    from: NaiveDate,
    to: NaiveDate,
    stats: ParseStats,
    config: &AnalysisConfig,
) -> anyhow::Result<ThreatReport> {
    let allowlist = Allowlist::parse(&config.allowlist.cidrs)?;
    let admin_ports = config.ports.admin_set();

    let mut profiles = offenders::build_profiles(entries, &admin_ports);
    let total_sources = u32::try_from(profiles.len()).unwrap_or(u32::MAX);
    profiles.retain(|profile| !allowlist.contains(&profile.ip));

    let mut findings = scan::detect(entries, &config.thresholds, &allowlist);
    findings.extend(bruteforce::detect_bruteforce(
        entries,
        &config.thresholds,
        &admin_ports,
        &allowlist,
    ));
    findings.extend(bruteforce::detect_distributed(
        entries,
        &config.thresholds,
        &allowlist,
    ));
    findings.extend(persistence_findings(&profiles, &config.thresholds));

    attach_findings(&mut profiles, &findings);
    scoring::apply_scores(&mut profiles, &config.scoring);

    profiles.retain(|profile| profile.risk_score >= config.thresholds.min_score);
    sort_profiles(&mut profiles);
    sort_findings(&mut findings);

    let coverage = coverage::build_coverage(entries, from, to, stats);
    let subnets = subnets::build_subnets(
        entries,
        &config.subnets,
        config.thresholds.subnet_min_sources,
    );
    let summary = build_summary(total_sources, &profiles, findings.len());

    Ok(ThreatReport {
        from,
        to,
        profiles,
        findings,
        subnets,
        coverage,
        summary,
    })
}

fn persistence_findings(profiles: &[SourceProfile], thresholds: &Thresholds) -> Vec<ThreatFinding> {
    profiles
        .iter()
        .filter(|profile| {
            profile.active_days >= thresholds.persistence_min_days
                && profile.total_blocks >= thresholds.persistence_min_blocks
        })
        .map(|profile| ThreatFinding {
            kind: ThreatKind::PersistentSource,
            source_ip: Some(profile.ip.clone()),
            target_ip: None,
            target_port: None,
            first_seen: profile.first_seen,
            last_seen: profile.last_seen,
            occurrences: profile.active_days,
            peak: profile.total_blocks,
            evidence: format!(
                "{} active days and {} blocked attempts",
                profile.active_days, profile.total_blocks
            ),
            severity: Severity::Medium,
        })
        .collect()
}

fn attach_findings(profiles: &mut [SourceProfile], findings: &[ThreatFinding]) {
    let index: HashMap<String, usize> = profiles
        .iter()
        .enumerate()
        .map(|(position, profile)| (profile.ip.clone(), position))
        .collect();

    for finding in findings {
        let Some(ip) = finding.source_ip.as_deref() else {
            continue;
        };
        let Some(&position) = index.get(ip) else {
            continue;
        };
        let profile = &mut profiles[position];
        if !profile.findings.contains(&finding.kind) {
            profile.findings.push(finding.kind);
        }
    }
}

fn sort_profiles(profiles: &mut [SourceProfile]) {
    profiles.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| b.total_blocks.cmp(&a.total_blocks))
            .then_with(|| a.ip.cmp(&b.ip))
    });
}

fn sort_findings(findings: &mut [ThreatFinding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.occurrences.cmp(&a.occurrences))
            .then_with(|| a.source_ip.cmp(&b.source_ip))
            .then_with(|| a.target_ip.cmp(&b.target_ip))
            .then_with(|| a.target_port.cmp(&b.target_port))
            .then_with(|| a.kind.cmp(&b.kind))
    });
}

fn build_summary(
    total_sources: u32,
    profiles: &[SourceProfile],
    total_findings: usize,
) -> ThreatSummary {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    for profile in profiles {
        match profile.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
        }
    }

    ThreatSummary {
        total_sources,
        ranked_sources: u32::try_from(profiles.len()).unwrap_or(u32::MAX),
        critical,
        high,
        medium,
        low,
        total_findings,
        top_source: profiles.first().map(|profile| profile.ip.clone()),
        top_score: profiles.first().map_or(0, |profile| profile.risk_score),
    }
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

    fn scan_entries() -> Vec<LogEntry> {
        (1..=10)
            .map(|port| entry(day(), "203.0.113.10", "192.168.1.1", port))
            .collect()
    }

    #[test]
    fn test_analyze_flags_a_port_scan_port() {
        let report = analyze(
            &scan_entries(),
            day(),
            day(),
            ParseStats::default(),
            &AnalysisConfig::default(),
        )
        .unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].kind, ThreatKind::PortScan);
        assert_eq!(report.profiles.len(), 1);
        assert_eq!(report.profiles[0].ip, "203.0.113.10");
        assert!(report.profiles[0].findings.contains(&ThreatKind::PortScan));
        assert_eq!(report.profiles[0].risk_score, 41);
        assert_eq!(report.profiles[0].severity, Severity::Medium);
        assert_eq!(report.summary.ranked_sources, 1);
        assert_eq!(report.summary.top_source.as_deref(), Some("203.0.113.10"));
    }

    #[test]
    fn test_allowlist_removes_profiles_and_findings() {
        let mut config = AnalysisConfig::default();
        config.allowlist.cidrs = vec!["203.0.113.0/24".to_string()];

        let report = analyze(
            &scan_entries(),
            day(),
            day(),
            ParseStats::default(),
            &config,
        )
        .unwrap();

        assert!(report.profiles.is_empty());
        assert!(report.findings.is_empty());
        assert_eq!(report.summary.total_sources, 1);
        assert_eq!(report.summary.ranked_sources, 0);
    }

    #[test]
    fn test_min_score_filters_the_ranking() {
        let mut config = AnalysisConfig::default();
        config.thresholds.min_score = 100;

        let report = analyze(
            &scan_entries(),
            day(),
            day(),
            ParseStats::default(),
            &config,
        )
        .unwrap();

        assert!(report.profiles.is_empty());
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.summary.ranked_sources, 0);
    }

    #[test]
    fn test_clean_traffic_produces_no_findings() {
        let entries = vec![entry(day(), "192.168.1.50", "192.168.1.1", 443)];

        let report = analyze(
            &entries,
            day(),
            day(),
            ParseStats::default(),
            &AnalysisConfig::default(),
        )
        .unwrap();

        assert!(report.findings.is_empty());
        assert!(report.profiles.is_empty());
    }

    #[test]
    fn test_persistent_source_is_flagged_and_scored() {
        let day2 = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let day3 = NaiveDate::from_ymd_opt(2026, 6, 30).unwrap();
        let mut entries = Vec::new();
        for date in [day(), day2, day3] {
            for _ in 0..10 {
                entries.push(entry(date, "203.0.113.10", "192.168.1.1", 22));
            }
        }

        let report = analyze(
            &entries,
            day(),
            day3,
            ParseStats::default(),
            &AnalysisConfig::default(),
        )
        .unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].kind, ThreatKind::PersistentSource);
        assert_eq!(report.profiles.len(), 1);
        assert_eq!(report.profiles[0].active_days, 3);
        assert!(report.profiles[0].risk_score >= 25);
    }
}
