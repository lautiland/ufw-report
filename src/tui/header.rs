use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use super::app::App;

pub const TAB_TITLES: &[&str] = &[" Overview ", " Daily ", " Hourly ", " Raw "];

pub fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let title = Span::styled(
        " ufw-report ",
        Style::default()
            .fg(Color::White)
            .bg(Color::Blue)
            .add_modifier(Modifier::BOLD),
    );

    let mut tab_spans = vec![title];
    for (i, tab) in TAB_TITLES.iter().enumerate() {
        let style = if i == app.current_tab {
            Style::default()
                .fg(Color::Black)
                .bg(Color::LightYellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White).bg(Color::DarkGray)
        };
        let prefix = if i > 0 { " " } else { "" };
        tab_spans.push(Span::styled(format!("{prefix}{tab}"), style));
    }

    let header = Paragraph::new(Line::from(tab_spans));
    frame.render_widget(header, area);
}
