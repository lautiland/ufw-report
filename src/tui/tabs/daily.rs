use crate::models::AggregatedData;
use crate::tui::widgets::bar_chart::{build_daily_bars, to_u16_clamped};

use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{BarChart, Block, Borders, Paragraph},
    Frame,
};

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

    let effective_idx = effective_idx.min(data.days.len() - 1);
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

    if !result.show_all && area.height > 0 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{build_aggregated, DailyReport, HourBreak, IpEntry, PortEntry};
    use chrono::NaiveDate;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::collections::HashMap;

    fn report(day: u32) -> DailyReport {
        DailyReport {
            date: NaiveDate::from_ymd_opt(2026, 6, day).unwrap(),
            total_blocked: 1,
            hourly: vec![HourBreak { hour: 10, count: 1 }],
            top_ips: Vec::<IpEntry>::new(),
            top_ports: Vec::<PortEntry>::new(),
            protocols: HashMap::new(),
        }
    }

    #[test]
    fn test_render_daily_with_zero_height_does_not_panic() {
        let mut terminal = Terminal::new(TestBackend::new(80, 4)).unwrap();
        let data = build_aggregated((1..=30).map(report).collect(), &[]);

        terminal
            .draw(|frame| render_daily(frame, Rect::new(0, 0, 20, 0), &data, 0))
            .unwrap();
    }
}
