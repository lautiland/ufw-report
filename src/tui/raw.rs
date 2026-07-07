use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table},
    Frame,
};

use crate::domain::Direction as UfwDirection;

use super::app::App;

pub fn render_raw(frame: &mut Frame, area: Rect, app: &App) {
    let entries = &app.entries;
    let total_entries = entries.len();
    let max_visible = (area.height as usize).saturating_sub(3).min(20);
    let max_scroll = total_entries.saturating_sub(max_visible);
    let scroll = app.raw_scroll.min(max_scroll);

    let rows: Vec<Row> = entries
        .iter()
        .skip(scroll)
        .take(max_visible)
        .map(|e| {
            Row::new(vec![
                Cell::from(e.date.format("%m/%d").to_string()),
                Cell::from(format!("{:02}", e.hour)),
                Cell::from(if e.src_ip.len() > 18 {
                    format!("{}..", &e.src_ip[..18])
                } else {
                    e.src_ip.clone()
                }),
                Cell::from(e.dst_ip.as_deref().unwrap_or("-").to_string()),
                Cell::from(e.dst_port.map_or("-".to_string(), |p| p.to_string())),
                Cell::from(e.protocol.as_deref().unwrap_or("-").to_string()),
                Cell::from(match e.direction {
                    UfwDirection::Incoming => "IN",
                    UfwDirection::Outgoing => "OUT",
                    UfwDirection::Unknown => "?",
                }),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(6),
        Constraint::Length(3),
        Constraint::Length(20),
        Constraint::Length(20),
        Constraint::Length(6),
        Constraint::Length(5),
        Constraint::Length(4),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "Date", "Hr", "Src IP", "Dst IP", "DPT", "Proto", "Dir",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().title(" Raw Logs ").borders(Borders::ALL));

    frame.render_widget(table, area);

    if total_entries > max_visible {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        let mut state =
            ScrollbarState::new(total_entries.saturating_sub(max_visible)).position(scroll);
        frame.render_stateful_widget(scrollbar, area, &mut state);
    }
}
