use std::collections::HashMap;
use std::hash::Hash;

use chrono::{Duration, NaiveDateTime};

/// One non-overlapping window that reached the configured threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WindowHit {
    pub start: NaiveDateTime,
    pub end: NaiveDateTime,
    pub peak: u64,
}

impl WindowHit {
    #[must_use]
    pub(crate) const fn new(start: NaiveDateTime, end: NaiveDateTime, peak: u64) -> Self {
        Self { start, end, peak }
    }
}

/// Converts a positive minute count into a `chrono` duration.
///
/// The configuration validates the range, so this only guards internal callers.
#[must_use]
pub(crate) fn window_from_minutes(minutes: u32) -> Duration {
    debug_assert!(minutes > 0, "window minutes must be positive");
    Duration::minutes(i64::from(minutes.max(1)))
}

/// Finds non-overlapping windows per key where the distinct value count reaches
/// `threshold`.
///
/// Items are grouped by key, sorted chronologically, and walked with two
/// pointers. After a hit the window is cleared, so one continuous burst yields
/// one occurrence instead of one finding per entry.
pub(crate) fn distinct_hits<K, V>(
    items: Vec<(K, NaiveDateTime, V)>,
    window: Duration,
    threshold: u64,
) -> HashMap<K, Vec<WindowHit>>
where
    K: Eq + Hash + Copy,
    V: Eq + Hash + Copy,
{
    let mut grouped: HashMap<K, Vec<(NaiveDateTime, V)>> = HashMap::new();
    for (key, timestamp, value) in items {
        grouped.entry(key).or_default().push((timestamp, value));
    }

    let mut hits: HashMap<K, Vec<WindowHit>> = HashMap::new();
    for (key, mut points) in grouped {
        points.sort_unstable_by_key(|(timestamp, _)| *timestamp);

        let mut counts: HashMap<V, usize> = HashMap::new();
        let mut left = 0;
        for right in 0..points.len() {
            *counts.entry(points[right].1).or_insert(0) += 1;
            while points[right].0 - points[left].0 >= window {
                let value = points[left].1;
                if let Some(count) = counts.get_mut(&value) {
                    *count -= 1;
                    if *count == 0 {
                        counts.remove(&value);
                    }
                }
                left += 1;
            }

            let distinct = u64::try_from(counts.len()).unwrap_or(u64::MAX);
            if distinct >= threshold {
                hits.entry(key).or_default().push(WindowHit::new(
                    points[left].0,
                    points[right].0,
                    distinct,
                ));
                counts.clear();
                left = right + 1;
            }
        }
    }

    hits
}

/// Finds non-overlapping windows where the number of events reaches
/// `threshold`.
pub(crate) fn count_hits(
    mut times: Vec<NaiveDateTime>,
    window: Duration,
    threshold: u64,
) -> Vec<WindowHit> {
    times.sort_unstable();
    let mut hits = Vec::new();
    let mut left = 0;
    for right in 0..times.len() {
        while times[right] - times[left] >= window {
            left += 1;
        }
        let count = u64::try_from(right - left + 1).unwrap_or(u64::MAX);
        if count >= threshold {
            hits.push(WindowHit::new(times[left], times[right], count));
            left = right + 1;
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn at(hour: u32, minute: u32, second: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 6, 28)
            .unwrap()
            .and_hms_opt(hour, minute, second)
            .unwrap()
    }

    #[test]
    fn test_distinct_hit_crosses_an_hour_boundary() {
        let base = at(10, 59, 30);
        let items: Vec<(&str, NaiveDateTime, u16)> = (0..10)
            .map(|offset| {
                (
                    "203.0.113.10",
                    base + Duration::seconds(offset * 10),
                    u16::try_from(offset + 1).unwrap(),
                )
            })
            .collect();

        let hits = distinct_hits(items, window_from_minutes(60), 10);

        let source_hits = hits.get("203.0.113.10").unwrap();
        assert_eq!(source_hits.len(), 1);
        assert_eq!(source_hits[0].peak, 10);
        assert_eq!(source_hits[0].start, at(10, 59, 30));
        assert_eq!(source_hits[0].end, at(11, 1, 0));
    }

    #[test]
    fn test_narrow_window_suppresses_the_same_burst() {
        let base = at(10, 59, 30);
        let items: Vec<(&str, NaiveDateTime, u16)> = (0..10)
            .map(|offset| {
                (
                    "203.0.113.10",
                    base + Duration::seconds(offset * 10),
                    u16::try_from(offset + 1).unwrap(),
                )
            })
            .collect();

        let hits = distinct_hits(items, window_from_minutes(1), 10);

        assert_eq!(hits.len(), 0);
    }

    #[test]
    fn test_hits_are_non_overlapping() {
        let items: Vec<(&str, NaiveDateTime, u16)> = (0..20)
            .map(|offset| ("203.0.113.10", at(10, u32::from(offset), 0), offset + 1))
            .collect();

        let hits = distinct_hits(items, window_from_minutes(60), 10);

        let source_hits = hits.get("203.0.113.10").unwrap();
        assert_eq!(source_hits.len(), 2);
        assert_eq!(source_hits[0].peak, 10);
        assert_eq!(source_hits[1].peak, 10);
        assert!(source_hits[0].end < source_hits[1].start);
    }

    #[test]
    fn test_count_hits_detects_a_burst() {
        let times: Vec<NaiveDateTime> = (0..20).map(|_| at(10, 0, 0)).collect();

        let hits = count_hits(times, window_from_minutes(60), 20);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].peak, 20);
    }

    #[test]
    fn test_count_hits_drops_events_outside_the_window() {
        let mut times: Vec<NaiveDateTime> = (0..10).map(|_| at(9, 0, 0)).collect();
        times.extend((0..10).map(|_| at(11, 0, 0)));

        let hits = count_hits(times, window_from_minutes(60), 15);

        assert_eq!(hits.len(), 0);
    }
}
