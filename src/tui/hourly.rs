use std::collections::HashMap;

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{
        Bar, BarChart, Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table,
    },
    Frame,
};

use crate::domain::{Direction as UfwDirection, LogEntry};

use super::app::App;

#[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
pub fn render_hourly(frame: &mut Frame, area: Rect, app: &App) {
    let data = &app.data;

    if data.days.is_empty() {
        let msg = Paragraph::new("No day selected — go to Daily tab and press Enter")
            .block(Block::default().borders(Borders::ALL).title(" Hourly "))
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(msg, area);
        return;
    }

    let day_idx = app
        .selected_day_index
        .unwrap_or_else(|| data.days.len().saturating_sub(1))
        .min(data.days.len().saturating_sub(1));
    let day = &data.days[day_idx];

    let effective_hour = app
        .selected_hour
        .or_else(|| App::last_hour_for_day(day))
        .unwrap_or(0)
        .min(23);

    let num_hours = 24usize;
    let avail = (area.width as usize).saturating_sub(2);
    let gap = 1usize;
    let total_gaps = num_hours.saturating_sub(1) * gap;

    let bar_width = if avail > total_gaps {
        ((avail - total_gaps) / num_hours).clamp(1, 6)
    } else {
        1usize
    };

    let max_count = day.hourly.iter().map(|h| h.count).max().unwrap_or(1).max(1);

    let mut hourly_map: HashMap<u32, u64> = HashMap::new();
    for h in &day.hourly {
        hourly_map.insert(h.hour, h.count);
    }

    let bars: Vec<Bar> = (0..24)
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
        .collect();

    let hourly_entries: Vec<&LogEntry> = app
        .entries
        .iter()
        .filter(|e| e.date == day.date && e.hour == effective_hour)
        .collect();

    let bar_area_height = if hourly_entries.is_empty() { 5 } else { 7 };

    let chunks = Layout::vertical([Constraint::Length(bar_area_height), Constraint::Min(0)])
        .areas::<2>(area);
    let [chart_area, entries_area] = chunks;

    let chart = BarChart::new(bars)
        .block(
            Block::default()
                .title(format!(
                    " Hourly: {}  (↑↓ hour {:02}:00, ←→ day) ",
                    day.date, effective_hour
                ))
                .borders(Borders::ALL),
        )
        .max(max_count)
        .bar_width(bar_width as u16)
        .bar_gap(gap as u16);

    frame.render_widget(chart, chart_area);

    if hourly_entries.is_empty() {
        let msg = Paragraph::new("No entries for this hour")
            .block(Block::default().borders(Borders::ALL).title(" Logs "))
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(msg, entries_area);
        return;
    }

    let max_visible = (entries_area.height as usize).saturating_sub(3).max(1);
    let max_scroll = hourly_entries.len().saturating_sub(max_visible);
    let scroll = app.hourly_scroll.min(max_scroll);

    let rows: Vec<Row> = hourly_entries
        .iter()
        .skip(scroll)
        .take(max_visible)
        .map(|e| {
            let port = e.dst_port.map_or("-".to_string(), |p| p.to_string());
            Row::new(vec![
                Cell::from(if e.src_ip.len() > 18 {
                    format!("{}..", &e.src_ip[..18])
                } else {
                    e.src_ip.clone()
                }),
                Cell::from(e.dst_ip.as_deref().unwrap_or("-").to_string()),
                Cell::from(e.protocol.as_deref().unwrap_or("-").to_string()),
                Cell::from(port),
                Cell::from(match e.direction {
                    UfwDirection::Incoming => "IN",
                    UfwDirection::Outgoing => "OUT",
                    UfwDirection::Unknown => "?",
                }),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(20),
        Constraint::Length(20),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(4),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["Src IP", "Dst IP", "Proto", "Port", "Dir"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .title(format!(" Logs ({} entries) ", hourly_entries.len()))
                .borders(Borders::ALL),
        );

    frame.render_widget(table, entries_area);

    if hourly_entries.len() > max_visible {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        let mut state =
            ScrollbarState::new(hourly_entries.len().saturating_sub(max_visible)).position(scroll);
        frame.render_stateful_widget(scrollbar, entries_area, &mut state);
    }
}
