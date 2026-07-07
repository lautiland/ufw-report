use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use super::app::App;

pub fn render_status(frame: &mut Frame, area: Rect, _app: &App) {
    let text = Line::from(vec![
        Span::styled("[Tab]", Style::default().fg(Color::Cyan)),
        Span::raw(" Tab "),
        Span::styled("[←→]", Style::default().fg(Color::Cyan)),
        Span::raw("Day/Hour "),
        Span::styled("[↑↓]", Style::default().fg(Color::Cyan)),
        Span::raw("Scroll "),
        Span::styled("[Enter]", Style::default().fg(Color::Cyan)),
        Span::raw("Hourly "),
        Span::styled("[q]", Style::default().fg(Color::Cyan)),
        Span::raw("Quit"),
    ]);
    let status = Paragraph::new(text).style(Style::default().bg(Color::DarkGray).fg(Color::White));
    frame.render_widget(status, area);
}
