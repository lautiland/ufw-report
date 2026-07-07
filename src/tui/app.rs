use crate::domain::{AggregatedData, DailyReport, LogEntry};

pub struct App {
    pub data: AggregatedData,
    pub entries: Vec<LogEntry>,
    pub current_tab: usize,
    pub selected_day_index: Option<usize>,
    pub selected_hour: Option<u32>,
    pub scroll: usize,
    pub raw_scroll: usize,
    pub hourly_scroll: usize,
    pub running: bool,
}

impl App {
    pub fn new(data: AggregatedData, entries: Vec<LogEntry>) -> Self {
        Self {
            data,
            entries,
            current_tab: 0,
            selected_day_index: None,
            selected_hour: None,
            scroll: 0,
            raw_scroll: 0,
            hourly_scroll: 0,
            running: true,
        }
    }

    pub fn last_hour_for_day(day: &DailyReport) -> Option<u32> {
        day.hourly.iter().max_by_key(|h| h.hour).map(|h| h.hour)
    }

    pub fn prev_hour_with_data(day: &DailyReport, from_hour: u32) -> Option<u32> {
        day.hourly
            .iter()
            .filter(|h| h.count > 0 && h.hour < from_hour)
            .max_by_key(|h| h.hour)
            .map(|h| h.hour)
    }

    pub fn next_hour_with_data(day: &DailyReport, from_hour: u32) -> Option<u32> {
        day.hourly
            .iter()
            .filter(|h| h.count > 0 && h.hour > from_hour)
            .min_by_key(|h| h.hour)
            .map(|h| h.hour)
    }

    pub fn prev_day_with_data(days: &[DailyReport], from_idx: usize) -> Option<usize> {
        (0..from_idx).rev().find(|&i| days[i].total_blocked > 0)
    }

    pub fn next_day_with_data(days: &[DailyReport], from_idx: usize) -> Option<usize> {
        (from_idx + 1..days.len()).find(|&i| days[i].total_blocked > 0)
    }
}
