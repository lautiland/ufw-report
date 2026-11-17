use crate::models::{Severity, SourceProfile};

use super::config::ScoringConfig;

/// Computes the 0-100 risk score for one source profile.
///
/// Every component is capped so a single signal cannot dominate the ranking:
/// volume 25, ports 25, administrative hits 20, persistence 15, findings 20.
#[must_use]
pub(crate) fn score_profile(profile: &SourceProfile, config: &ScoringConfig) -> u8 {
    let volume = profile
        .total_blocks
        .saturating_add(1)
        .ilog10()
        .saturating_mul(config.volume_weight)
        .min(25);
    let ports = profile
        .distinct_dst_ports
        .saturating_mul(config.ports_weight)
        .min(25);
    let admin = profile
        .admin_port_hits
        .saturating_div(5)
        .saturating_mul(u64::from(config.admin_weight))
        .min(20);
    let admin = u32::try_from(admin).unwrap_or(u32::MAX);
    let persistence = profile
        .active_days
        .saturating_mul(config.persistence_weight)
        .min(15);
    let findings = u32::try_from(profile.findings.len())
        .unwrap_or(u32::MAX)
        .saturating_mul(config.finding_weight)
        .min(20);

    let total = volume
        .saturating_add(ports)
        .saturating_add(admin)
        .saturating_add(persistence)
        .saturating_add(findings)
        .min(100);

    u8::try_from(total).unwrap_or(100)
}

/// Scores every profile in place and updates its severity band.
pub(crate) fn apply_scores(profiles: &mut [SourceProfile], config: &ScoringConfig) {
    for profile in profiles {
        let score = score_profile(profile, config);
        profile.risk_score = score;
        profile.severity = Severity::from_score(score);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ThreatKind;
    use chrono::NaiveDate;

    fn profile() -> SourceProfile {
        SourceProfile {
            ip: "203.0.113.10".to_string(),
            total_blocks: 30,
            first_seen: NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            last_seen: NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            active_days: 2,
            distinct_dst_ports: 5,
            distinct_dst_ips: 1,
            admin_port_hits: 25,
            top_ports: Vec::new(),
            top_protocols: Vec::new(),
            findings: vec![ThreatKind::BruteForce, ThreatKind::PersistentSource],
            risk_score: 0,
            severity: Severity::Low,
        }
    }

    #[test]
    fn test_score_components_add_up() {
        // volume: ilog10(31) = 1 -> 8
        // ports: 5 * 2 = 10
        // admin: 25 / 5 * 1 = 5
        // persistence: 2 * 3 = 6
        // findings: 2 * 10 = 20
        let score = score_profile(&profile(), &ScoringConfig::default());
        assert_eq!(score, 49);
        assert_eq!(Severity::from_score(score), Severity::Medium);
    }

    #[test]
    fn test_score_is_clamped_to_100() {
        let mut profile = profile();
        profile.total_blocks = 1_000_000;
        profile.distinct_dst_ports = 100;
        profile.admin_port_hits = 1_000;
        profile.active_days = 100;
        profile.findings = vec![
            ThreatKind::PortScan,
            ThreatKind::HostSweep,
            ThreatKind::BruteForce,
            ThreatKind::DistributedBruteForce,
            ThreatKind::PersistentSource,
        ];

        let score = score_profile(&profile, &ScoringConfig::default());

        assert_eq!(score, 100);
        assert_eq!(Severity::from_score(score), Severity::Critical);
    }

    #[test]
    fn test_empty_profile_scores_zero() {
        let mut profile = profile();
        profile.total_blocks = 0;
        profile.distinct_dst_ports = 0;
        profile.admin_port_hits = 0;
        profile.active_days = 0;
        profile.findings.clear();

        let score = score_profile(&profile, &ScoringConfig::default());

        assert_eq!(score, 0);
        assert_eq!(Severity::from_score(score), Severity::Low);
    }

    #[test]
    fn test_apply_scores_updates_severity() {
        let mut profiles = vec![profile()];

        apply_scores(&mut profiles, &ScoringConfig::default());

        assert_eq!(profiles[0].risk_score, 49);
        assert_eq!(profiles[0].severity, Severity::Medium);
    }
}
