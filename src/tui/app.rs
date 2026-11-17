use crate::models::{AggregatedData, DailyReport, LogEntry, ThreatReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Daily,
    Hourly,
    Raw,
    Threats,
}

impl Tab {
    pub const ALL: [Self; 5] = [
        Self::Overview,
        Self::Daily,
        Self::Hourly,
        Self::Raw,
        Self::Threats,
    ];

    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Daily => 1,
            Self::Hourly => 2,
            Self::Raw => 3,
            Self::Threats => 4,
        }
    }

    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Overview => Self::Daily,
            Self::Daily => Self::Hourly,
            Self::Hourly => Self::Raw,
            Self::Raw => Self::Threats,
            Self::Threats => Self::Overview,
        }
    }

    #[must_use]
    pub const fn prev(self) -> Self {
        match self {
            Self::Overview => Self::Threats,
            Self::Daily => Self::Overview,
            Self::Hourly => Self::Daily,
            Self::Raw => Self::Hourly,
            Self::Threats => Self::Raw,
        }
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Daily => "Daily",
            Self::Hourly => "Hourly",
            Self::Raw => "Raw",
            Self::Threats => "Threats",
        }
    }

    #[must_use]
    pub const fn hint(self) -> &'static str {
        match self {
            Self::Overview => "↑↓ Scroll protocols  PgUp/PgDn Fast scroll",
            Self::Daily => "←→ Select day  Enter Hourly",
            Self::Hourly => "←→ Day  ↑↓ Hour  PgUp/PgDn Logs",
            Self::Raw => "↑↓ Scroll  PgUp/PgDn Fast scroll",
            Self::Threats => "↑↓ Select  PgUp/PgDn Page  v Sources/Networks",
        }
    }
}

/// Alternate table shown in the Threats tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatsView {
    Sources,
    Networks,
}

impl ThreatsView {
    #[must_use]
    pub const fn toggle(self) -> Self {
        match self {
            Self::Sources => Self::Networks,
            Self::Networks => Self::Sources,
        }
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Sources => "Threat Sources",
            Self::Networks => "Network Groups",
        }
    }
}

pub struct App {
    pub data: AggregatedData,
    pub entries: Vec<LogEntry>,
    pub threat: ThreatReport,
    pub current_tab: Tab,
    pub threats_view: ThreatsView,
    pub threat_selection: usize,
    pub selected_day_index: Option<usize>,
    pub selected_hour: Option<u32>,
    pub scroll: usize,
    pub raw_scroll: usize,
    pub hourly_scroll: usize,
    pub running: bool,
}

impl App {
    #[must_use]
    pub fn new(data: AggregatedData, entries: Vec<LogEntry>, threat: ThreatReport) -> Self {
        Self {
            data,
            entries,
            threat,
            current_tab: Tab::Overview,
            threats_view: ThreatsView::Sources,
            threat_selection: 0,
            selected_day_index: None,
            selected_hour: None,
            scroll: 0,
            raw_scroll: 0,
            hourly_scroll: 0,
            running: true,
        }
    }

    #[must_use]
    pub fn threats_len(&self) -> usize {
        match self.threats_view {
            ThreatsView::Sources => self.threat.profiles.len(),
            ThreatsView::Networks => self.threat.subnets.len(),
        }
    }

    #[must_use]
    pub fn clamp_index(index: usize, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            index.min(len - 1)
        }
    }

    pub fn clamp_threat_selection(&mut self) {
        self.threat_selection = Self::clamp_index(self.threat_selection, self.threats_len());
    }

    pub fn move_threat_selection(&mut self, step: usize, forward: bool) {
        let len = self.threats_len();
        if len == 0 {
            self.threat_selection = 0;
            return;
        }
        let current = Self::clamp_index(self.threat_selection, len);
        self.threat_selection = if forward {
            current.saturating_add(step).min(len - 1)
        } else {
            current.saturating_sub(step)
        };
    }

    pub fn toggle_threats_view(&mut self) {
        self.threats_view = self.threats_view.toggle();
        self.threat_selection = 0;
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
    use crate::models::{build_aggregated, HourBreak, IpEntry, PortEntry};
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

    fn app() -> App {
        let date = NaiveDate::from_ymd_opt(2026, 6, 28).unwrap();
        App::new(
            build_aggregated(Vec::new(), &[]),
            Vec::new(),
            ThreatReport::empty(date, date),
        )
    }

    #[test]
    fn test_tab_cycles_forward_and_backward() {
        assert_eq!(Tab::Overview.next(), Tab::Daily);
        assert_eq!(Tab::Raw.next(), Tab::Threats);
        assert_eq!(Tab::Threats.next(), Tab::Overview);
        assert_eq!(Tab::Overview.prev(), Tab::Threats);
        assert_eq!(Tab::Threats.prev(), Tab::Raw);
        assert_eq!(Tab::Daily.prev(), Tab::Overview);
    }

    #[test]
    fn test_threats_view_toggles() {
        assert_eq!(ThreatsView::Sources.toggle(), ThreatsView::Networks);
        assert_eq!(ThreatsView::Networks.toggle(), ThreatsView::Sources);
    }

    #[test]
    fn test_threat_selection_is_clamped() {
        let mut app = app();
        app.threat_selection = 10;
        app.clamp_threat_selection();
        assert_eq!(app.threat_selection, 0);

        app.move_threat_selection(1, true);
        assert_eq!(app.threat_selection, 0);

        app.move_threat_selection(1, false);
        assert_eq!(app.threat_selection, 0);
    }

    #[test]
    fn test_toggle_resets_threat_selection() {
        let mut app = app();
        app.threat_selection = 3;
        app.toggle_threats_view();
        assert_eq!(app.threat_selection, 0);
        assert_eq!(app.threats_view, ThreatsView::Networks);
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
