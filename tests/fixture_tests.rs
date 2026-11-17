use std::path::PathBuf;

use chrono::NaiveDate;
use ufw_report::core::{parse_ufw_log_range_with_options, ParseOptions, ParseResult};
use ufw_report::models::Direction;

fn fixture_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ufw.log")
        .to_string_lossy()
        .into_owned()
}

fn reference_date() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 7, 10).unwrap()
}

fn parse(from: NaiveDate, to: NaiveDate) -> ParseResult {
    let options = ParseOptions {
        use_cache: false,
        reference_date: Some(reference_date()),
        ..ParseOptions::default()
    };
    parse_ufw_log_range_with_options(&fixture_path(), from, to, &options).unwrap()
}

fn june() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 6, 1).unwrap()
}

fn july() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 7, 31).unwrap()
}

#[test]
fn test_fixture_parses_all_blocked_entries() {
    let result = parse(june(), july());

    assert_eq!(result.all_entries.len(), 8);
    assert!(result
        .all_entries
        .iter()
        .all(|entry| entry.date >= june() && entry.date <= july()));
}

#[test]
fn test_fixture_splits_entries_by_month() {
    let june_result = parse(june(), NaiveDate::from_ymd_opt(2026, 6, 30).unwrap());
    assert_eq!(june_result.all_entries.len(), 5);
    assert_eq!(june_result.reports.len(), 30);

    let july_result = parse(NaiveDate::from_ymd_opt(2026, 7, 1).unwrap(), july());
    assert_eq!(july_result.all_entries.len(), 3);
    assert_eq!(july_result.reports.len(), 31);
}

#[test]
fn test_fixture_skips_allow_entries() {
    let result = parse(june(), july());

    assert!(result
        .all_entries
        .iter()
        .all(|entry| entry.src_ip != "1.2.3.4"));
}

#[test]
fn test_fixture_preserves_ipv6_and_protocols() {
    let result = parse(june(), july());

    let ipv6 = result
        .all_entries
        .iter()
        .find(|entry| entry.src_ip == "2001:db8::1")
        .expect("IPv6 entry should be parsed");
    assert_eq!(ipv6.protocol.as_deref(), Some("UDP"));
    assert_eq!(ipv6.dst_port, Some(53));

    let igmp = result
        .all_entries
        .iter()
        .find(|entry| entry.src_ip == "10.0.0.5")
        .expect("IGMP entry should be parsed");
    assert_eq!(igmp.protocol.as_deref(), Some("IGMP"));
    assert_eq!(igmp.direction, Direction::Outgoing);
}

#[test]
fn test_fixture_reports_account_for_every_entry() {
    let result = parse(june(), july());
    let total: u64 = result
        .reports
        .iter()
        .map(|report| report.total_blocked)
        .sum();

    assert_eq!(total, 8);
}
