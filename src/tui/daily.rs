use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Bar, BarChart, Block, Borders, Paragraph},
    Frame,
};

use super::app::App;

#[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
pub fn render_daily(frame: &mut Frame, area: Rect, app: &App) {
    let data = &app.data;

    if data.days.is_empty() {
        let msg = Paragraph::new("No data available")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Daily Activity "),
            )
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(msg, area);
        return;
    }

    let effective_idx = app
        .selected_day_index
        .unwrap_or_else(|| data.days.len().saturating_sub(1));

    let num_days = data.days.len();
    let avail = (area.width as usize).saturating_sub(2);
    let gap = 1usize;
    let total_gaps = num_days.saturating_sub(1) * gap;

    let bar_width = if avail > total_gaps {
        ((avail - total_gaps) / num_days).clamp(1, 12)
    } else {
        1usize
    };

    let bars_per_width = avail / (bar_width + gap);
    let show_all = bars_per_width >= num_days;

    let (bars, offset, max_count) = if show_all {
        let max_count = data
            .days
            .iter()
            .map(|d| d.total_blocked)
            .max()
            .unwrap_or(1)
            .max(1);
        (
            data.days
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    let style = if i == effective_idx {
                        Style::default().fg(Color::Yellow).bg(Color::DarkGray)
                    } else {
                        Style::default().fg(Color::Cyan)
                    };
                    Bar::with_label(d.date.format("%m/%d").to_string(), d.total_blocked)
                        .style(style)
                })
                .collect::<Vec<_>>(),
            0,
            max_count,
        )
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
        (
            data.days[offset..end]
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    let global_i = offset + i;
                    let style = if global_i == effective_idx {
                        Style::default().fg(Color::Yellow).bg(Color::DarkGray)
                    } else {
                        Style::default().fg(Color::Cyan)
                    };
                    Bar::with_label(d.date.format("%m/%d").to_string(), d.total_blocked)
                        .style(style)
                })
                .collect(),
            offset,
            max_count,
        )
    };

    let chart = BarChart::new(bars)
        .block(
            Block::default()
                .title(format!(
                    " Daily Activity  [{}]  (←→ select, Enter → hourly) ",
                    data.days[effective_idx].date
                ))
                .borders(Borders::ALL),
        )
        .max(max_count)
        .bar_width(bar_width as u16)
        .bar_gap(gap as u16);

    frame.render_widget(chart, area);

    if !show_all {
        let scroll_indicator = format!(
            " ◄ {} of {} ► ",
            offset + 1,
            num_days.saturating_sub(bars_per_width) + 1
        );
        let status = Paragraph::new(Line::from(vec![Span::styled(
            scroll_indicator,
            Style::default().fg(Color::DarkGray),
        )]))
        .alignment(ratatui::layout::Alignment::Center);
        let status_area = Rect {
            x: area.x,
            y: area.y + area.height - 1,
            width: area.width,
            height: 1,
        };
        frame.render_widget(status, status_area);
    }
}
