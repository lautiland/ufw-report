pub mod config;

pub(crate) mod allowlist;
pub(crate) mod coverage;
pub(crate) mod offenders;
pub(crate) mod subnets;
pub(crate) mod util;

use chrono::NaiveDate;

use crate::models::{LogEntry, ParseStats, ThreatReport, ThreatSummary};

pub use config::AnalysisConfig;

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
    let allowlist = allowlist::Allowlist::parse(&config.allowlist.cidrs)?;
    let admin_ports = config.ports.admin_set();

    let mut profiles = offenders::build_profiles(entries, &admin_ports);
    let total_sources = u32::try_from(profiles.len()).unwrap_or(u32::MAX);
    profiles.retain(|profile| !allowlist.contains(&profile.ip));

    let subnets = subnets::build_subnets(
        entries,
        &config.subnets,
        config.thresholds.subnet_min_sources,
    );
    let coverage = coverage::build_coverage(entries, from, to, stats);
    let ranked_sources = u32::try_from(profiles.len()).unwrap_or(u32::MAX);
    let summary = ThreatSummary {
        total_sources,
        ranked_sources,
        critical: 0,
        high: 0,
        medium: 0,
        low: ranked_sources,
        total_findings: 0,
        top_source: profiles.first().map(|profile| profile.ip.clone()),
        top_score: profiles.first().map_or(0, |profile| profile.risk_score),
    };

    Ok(ThreatReport {
        from,
        to,
        profiles,
        findings: Vec::new(),
        subnets,
        coverage,
        summary,
    })
}
