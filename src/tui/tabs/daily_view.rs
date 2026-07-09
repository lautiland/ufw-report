use crate::models::AggregatedData;

use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{BarChart, Block, Borders, Paragraph},
    Frame,
};

use super::daily::{build_daily_bars, to_u16_clamped};

pub(crate) fn render_daily(
    frame: &mut Frame,
    area: Rect,
    data: &AggregatedData,
    effective_idx: usize,
) {
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

    let result = build_daily_bars(data, effective_idx, area.width);

    let chart = BarChart::new(result.bars)
        .block(
            Block::default()
                .title(format!(
                    " Daily Activity  [{}]  (←→ select, Enter → hourly) ",
                    data.days[effective_idx].date
                ))
                .borders(Borders::ALL),
        )
        .max(result.max_count)
        .bar_width(to_u16_clamped(result.bar_width))
        .bar_gap(to_u16_clamped(result.gap));

    frame.render_widget(chart, area);

    if !result.show_all {
        let scroll_indicator = format!(
            " ◄ {} of {} ► ",
            result.offset + 1,
            result.num_days.saturating_sub(result.bars_per_width) + 1
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
