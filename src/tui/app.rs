use crate::models::{AggregatedData, DailyReport, LogEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Daily,
    Hourly,
    Raw,
}

impl Tab {
    pub const ALL: [Self; 4] = [Self::Overview, Self::Daily, Self::Hourly, Self::Raw];

    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Daily => 1,
            Self::Hourly => 2,
            Self::Raw => 3,
        }
    }

    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Overview => Self::Daily,
            Self::Daily => Self::Hourly,
            Self::Hourly => Self::Raw,
            Self::Raw => Self::Overview,
        }
    }

    #[must_use]
    pub const fn prev(self) -> Self {
        match self {
            Self::Overview => Self::Raw,
            Self::Daily => Self::Overview,
            Self::Hourly => Self::Daily,
            Self::Raw => Self::Hourly,
        }
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Daily => "Daily",
            Self::Hourly => "Hourly",
            Self::Raw => "Raw",
        }
    }

    #[must_use]
    pub const fn hint(self) -> &'static str {
        match self {
            Self::Overview => "↑↓ Scroll protocols  PgUp/PgDn Fast scroll",
            Self::Daily => "←→ Select day  Enter Hourly",
            Self::Hourly => "←→ Day  ↑↓ Hour  PgUp/PgDn Logs",
            Self::Raw => "↑↓ Scroll  PgUp/PgDn Fast scroll",
        }
    }
}

pub struct App {
    pub data: AggregatedData,
    pub entries: Vec<LogEntry>,
    pub current_tab: Tab,
    pub selected_day_index: Option<usize>,
    pub selected_hour: Option<u32>,
    pub scroll: usize,
    pub raw_scroll: usize,
    pub hourly_scroll: usize,
    pub running: bool,
}

impl App {
    #[must_use]
    pub fn new(data: AggregatedData, entries: Vec<LogEntry>) -> Self {
        Self {
            data,
            entries,
            current_tab: Tab::Overview,
            selected_day_index: None,
            selected_hour: None,
            scroll: 0,
            raw_scroll: 0,
            hourly_scroll: 0,
            running: true,
        }
    }

    #[must_use]
    pub fn last_hour_for_day(day: &DailyReport) -> Option<u32> {
        day.hourly.iter().max_by_key(|h| h.hour).map(|h| h.hour)
    }

    #[must_use]
    pub fn prev_hour_with_data(day: &DailyReport, from_hour: u32) -> Option<u32> {
        day.hourly
            .iter()
            .filter(|h| h.count > 0 && h.hour < from_hour)
            .max_by_key(|h| h.hour)
            .map(|h| h.hour)
    }

    #[must_use]
    pub fn next_hour_with_data(day: &DailyReport, from_hour: u32) -> Option<u32> {
        day.hourly
            .iter()
            .filter(|h| h.count > 0 && h.hour > from_hour)
            .min_by_key(|h| h.hour)
            .map(|h| h.hour)
    }

    #[must_use]
    pub fn prev_day_with_data(days: &[DailyReport], from_idx: usize) -> Option<usize> {
        (0..from_idx).rev().find(|&i| days[i].total_blocked > 0)
    }

    #[must_use]
    pub fn next_day_with_data(days: &[DailyReport], from_idx: usize) -> Option<usize> {
        (from_idx + 1..days.len()).find(|&i| days[i].total_blocked > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{HourBreak, IpEntry, PortEntry};
    use chrono::NaiveDate;
    use std::collections::HashMap;

    fn day(day_number: u32, total_blocked: u64, hours: &[u32]) -> DailyReport {
        DailyReport {
            date: NaiveDate::from_ymd_opt(2026, 6, day_number).unwrap(),
            total_blocked,
            hourly: hours
                .iter()
                .map(|hour| HourBreak {
                    hour: *hour,
                    count: 1,
                })
                .collect(),
            top_ips: Vec::<IpEntry>::new(),
            top_ports: Vec::<PortEntry>::new(),
            protocols: HashMap::new(),
        }
    }

    #[test]
    fn test_tab_cycles_forward_and_backward() {
        assert_eq!(Tab::Overview.next(), Tab::Daily);
        assert_eq!(Tab::Raw.next(), Tab::Overview);
        assert_eq!(Tab::Overview.prev(), Tab::Raw);
        assert_eq!(Tab::Daily.prev(), Tab::Overview);
    }

    #[test]
    fn test_day_navigation_skips_days_without_data() {
        let days = vec![
            day(1, 0, &[]),
            day(2, 3, &[1]),
            day(3, 0, &[]),
            day(4, 1, &[2]),
        ];

        assert_eq!(App::next_day_with_data(&days, 0), Some(1));
        assert_eq!(App::next_day_with_data(&days, 1), Some(3));
        assert_eq!(App::next_day_with_data(&days, 3), None);
        assert_eq!(App::prev_day_with_data(&days, 3), Some(1));
        assert_eq!(App::prev_day_with_data(&days, 1), None);
    }

    #[test]
    fn test_hour_navigation_skips_hours_without_data() {
        let day = day(1, 4, &[1, 3, 5]);

        assert_eq!(App::last_hour_for_day(&day), Some(5));
        assert_eq!(App::next_hour_with_data(&day, 1), Some(3));
        assert_eq!(App::next_hour_with_data(&day, 5), None);
        assert_eq!(App::prev_hour_with_data(&day, 5), Some(3));
        assert_eq!(App::prev_hour_with_data(&day, 1), None);
    }
}
