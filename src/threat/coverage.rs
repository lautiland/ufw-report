use std::collections::HashSet;

use chrono::NaiveDate;

use crate::models::{CoverageSummary, LogEntry, ParseStats};

/// Computes hourly coverage for the requested range.
///
/// Missing hours are expected when the log was rotated or when the machine was
/// off; they are reported instead of silently treated as "no attacks".
pub(crate) fn build_coverage(
    entries: &[LogEntry],
    from: NaiveDate,
    to: NaiveDate,
    stats: ParseStats,
) -> CoverageSummary {
    let days = if to < from {
        0
    } else {
        (to - from).num_days().max(0) + 1
    };
    let hours_in_range = u32::try_from(days.saturating_mul(24)).unwrap_or(u32::MAX);

    let present: HashSet<(NaiveDate, u32)> = entries
        .iter()
        .map(|entry| (entry.date, entry.hour))
        .collect();
    let hours_with_data = u32::try_from(present.len()).unwrap_or(u32::MAX);
    let missing_hours = hours_in_range.saturating_sub(hours_with_data);

    let mut longest_gap_hours = 0u32;
    let mut current_gap = 0u32;
    let mut date = from;
    while date <= to {
        for hour in 0..24 {
            if present.contains(&(date, hour)) {
                current_gap = 0;
            } else {
                current_gap += 1;
                longest_gap_hours = longest_gap_hours.max(current_gap);
            }
        }
        date += chrono::Duration::days(1);
    }

    let coverage_pct = if hours_in_range == 0 {
        0.0
    } else {
        let pct = f64::from(hours_with_data) / f64::from(hours_in_range) * 100.0;
        (pct * 100.0).round() / 100.0
    };

    CoverageSummary {
        stats,
        hours_in_range,
        hours_with_data,
        missing_hours,
        longest_gap_hours,
        coverage_pct,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Direction;

    fn entry(date: NaiveDate, hour: u32) -> LogEntry {
        let timestamp = date
            .and_hms_opt(hour, 0, 0)
            .expect("test timestamp should be valid");
        let mut entry = LogEntry::new(timestamp, "10.0.0.1".to_string());
        entry.dst_port = Some(22);
        entry.protocol = Some("TCP".to_string());
        entry.direction = Direction::Incoming;
        entry
    }

    #[test]
    fn test_coverage_counts_hours_and_gaps() {
        let day1 = NaiveDate::from_ymd_opt(2026, 6, 28).unwrap();
        let day2 = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let entries = vec![entry(day1, 12), entry(day2, 0)];

        let coverage = build_coverage(&entries, day1, day2, ParseStats::default());

        assert_eq!(coverage.hours_in_range, 48);
        assert_eq!(coverage.hours_with_data, 2);
        assert_eq!(coverage.missing_hours, 46);
        assert_eq!(coverage.longest_gap_hours, 23);
        assert!((coverage.coverage_pct - 4.17).abs() < 0.01);
    }

    #[test]
    fn test_coverage_deduplicates_hours() {
        let day = NaiveDate::from_ymd_opt(2026, 6, 28).unwrap();
        let entries = vec![entry(day, 10), entry(day, 10), entry(day, 11)];

        let coverage = build_coverage(&entries, day, day, ParseStats::default());

        assert_eq!(coverage.hours_in_range, 24);
        assert_eq!(coverage.hours_with_data, 2);
        assert_eq!(coverage.missing_hours, 22);
    }

    #[test]
    fn test_full_coverage_has_no_gaps() {
        let day = NaiveDate::from_ymd_opt(2026, 6, 28).unwrap();
        let entries: Vec<LogEntry> = (0..24).map(|hour| entry(day, hour)).collect();

        let coverage = build_coverage(&entries, day, day, ParseStats::default());

        assert_eq!(coverage.hours_with_data, 24);
        assert_eq!(coverage.missing_hours, 0);
        assert_eq!(coverage.longest_gap_hours, 0);
        assert!((coverage.coverage_pct - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_empty_range_is_zero() {
        let day = NaiveDate::from_ymd_opt(2026, 6, 28).unwrap();
        let coverage = build_coverage(&[], day, day, ParseStats::default());

        assert_eq!(coverage.hours_in_range, 24);
        assert_eq!(coverage.hours_with_data, 0);
        assert_eq!(coverage.missing_hours, 24);
        assert_eq!(coverage.longest_gap_hours, 24);
        assert!((coverage.coverage_pct - 0.0).abs() < f64::EPSILON);
    }
}
