use crate::models::DailyReport;

use ratatui::{
    style::{Color, Style},
    widgets::Bar,
};

pub(crate) fn to_u16_clamped(v: usize) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

pub(crate) struct DailyBarsResult {
    pub bars: Vec<Bar<'static>>,
    pub offset: usize,
    pub max_count: u64,
    pub bar_width: usize,
    pub gap: usize,
    pub show_all: bool,
    pub num_days: usize,
    pub bars_per_width: usize,
}

pub(crate) fn build_daily_bars(
    data: &crate::models::AggregatedData,
    effective_idx: usize,
    area_width: u16,
) -> DailyBarsResult {
    let num_days = data.days.len();
    let avail = (area_width as usize).saturating_sub(2);
    let gap = 1usize;
    let total_gaps = num_days.saturating_sub(1) * gap;

    let bar_width = if avail > total_gaps {
        ((avail - total_gaps) / num_days).clamp(1, 12)
    } else {
        1usize
    };

    let bars_per_width = avail / (bar_width + gap);
    let show_all = bars_per_width >= num_days;

    if show_all {
        let max_count = data
            .days
            .iter()
            .map(|d| d.total_blocked)
            .max()
            .unwrap_or(1)
            .max(1);
        let bars = data
            .days
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let style = if i == effective_idx {
                    Style::default().fg(Color::Yellow).bg(Color::DarkGray)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                Bar::with_label(d.date.format("%m/%d").to_string(), d.total_blocked).style(style)
            })
            .collect();
        DailyBarsResult {
            bars,
            offset: 0,
            max_count,
            bar_width,
            gap,
            show_all: true,
            num_days,
            bars_per_width,
        }
    } else {
        let max_offset = num_days.saturating_sub(bars_per_width);
        let offset = effective_idx
            .saturating_sub(bars_per_width)
            .saturating_add(1)
            .min(max_offset);
        let end = (offset + bars_per_width).min(num_days);
        let max_count = data.days[offset..end]
            .iter()
            .map(|d| d.total_blocked)
            .max()
            .unwrap_or(1)
            .max(1);
        let bars = data.days[offset..end]
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let global_i = offset + i;
                let style = if global_i == effective_idx {
                    Style::default().fg(Color::Yellow).bg(Color::DarkGray)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                Bar::with_label(d.date.format("%m/%d").to_string(), d.total_blocked).style(style)
            })
            .collect();
        DailyBarsResult {
            bars,
            offset,
            max_count,
            bar_width,
            gap,
            show_all: false,
            num_days,
            bars_per_width,
        }
    }
}

pub(crate) fn build_hourly_bars(day: &DailyReport, effective_hour: u32) -> Vec<Bar<'static>> {
    use std::collections::HashMap;

    let mut hourly_map: HashMap<u32, u64> = HashMap::new();
    for h in &day.hourly {
        hourly_map.insert(h.hour, h.count);
    }

    (0..24)
        .map(|hour| {
            let count = hourly_map.get(&hour).copied().unwrap_or(0);
            let label = format!("{hour:02}");
            let style = if hour == effective_hour {
                Style::default().fg(Color::Yellow)
            } else if count > 0 {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            Bar::with_label(label, count).style(style)
        })
        .collect()
}
