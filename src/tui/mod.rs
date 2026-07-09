pub mod app;
pub mod tabs;
pub mod widgets;

use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame, Terminal,
};

use crate::models::{AggregatedData, LogEntry};

use self::app::App;

const TAB_TITLES: &[&str] = &[" Overview ", " Daily ", " Hourly ", " Raw "];

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = io::stdout().execute(LeaveAlternateScreen);
}

/// # Errors
///
/// Returns an error if the terminal cannot be initialized or events fail to read.
pub fn run_tui(data: AggregatedData, entries: Vec<LogEntry>) -> anyhow::Result<()> {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        restore_terminal();
        original_hook(panic);
    }));

    let result = run_tui_inner(data, entries);

    if result.is_err() {
        restore_terminal();
    }

    result
}

fn run_tui_inner(data: AggregatedData, entries: Vec<LogEntry>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(data, entries);

    while app.running {
        terminal.draw(|frame| ui(frame, &mut app))?;
        handle_events(&mut app)?;
    }

    restore_terminal();
    Ok(())
}

fn handle_left_key(app: &mut App) {
    match app.current_tab {
        1 if !app.data.days.is_empty() => {
            let last = app.data.days.len().saturating_sub(1);
            let idx = app.selected_day_index.unwrap_or(last);
            if let Some(prev) = App::prev_day_with_data(&app.data.days, idx) {
                app.selected_day_index = Some(prev);
            }
        }
        2 if !app.data.days.is_empty() => {
            let last = app.data.days.len().saturating_sub(1);
            let idx = app.selected_day_index.unwrap_or(last).min(last);
            let day = &app.data.days[idx];
            let default_h = App::last_hour_for_day(day).unwrap_or(0);
            let h = app.selected_hour.unwrap_or(default_h);
            if let Some(prev_h) = App::prev_hour_with_data(day, h) {
                app.selected_hour = Some(prev_h);
            } else if let Some(prev) = App::prev_day_with_data(&app.data.days, idx) {
                app.selected_day_index = Some(prev);
                app.selected_hour = App::last_hour_for_day(&app.data.days[prev]);
            }
            app.hourly_scroll = 0;
        }
        _ => {}
    }
}

fn handle_right_key(app: &mut App) {
    match app.current_tab {
        1 if !app.data.days.is_empty() => {
            let last = app.data.days.len().saturating_sub(1);
            let idx = app.selected_day_index.unwrap_or(last);
            if let Some(next) = App::next_day_with_data(&app.data.days, idx) {
                app.selected_day_index = Some(next);
            }
        }
        2 if !app.data.days.is_empty() => {
            let n = app.data.days.len();
            let last = n.saturating_sub(1);
            let idx = app.selected_day_index.unwrap_or(last).min(last);
            let day = &app.data.days[idx];
            let default_h = App::last_hour_for_day(day).unwrap_or(0);
            let h = app.selected_hour.unwrap_or(default_h);
            if let Some(next_h) = App::next_hour_with_data(day, h) {
                app.selected_hour = Some(next_h);
            } else if let Some(next) = App::next_day_with_data(&app.data.days, idx) {
                app.selected_day_index = Some(next);
                let next_day = &app.data.days[next];
                app.selected_hour = next_day
                    .hourly
                    .iter()
                    .filter(|hb| hb.count > 0)
                    .min_by_key(|hb| hb.hour)
                    .map(|hb| hb.hour);
            }
            app.hourly_scroll = 0;
        }
        _ => {}
    }
}

fn handle_scroll(app: &mut App, step: usize, direction: i8) {
    let apply = |current: usize, delta: i8| -> usize {
        if delta > 0 {
            current.saturating_add(step)
        } else {
            current.saturating_sub(step)
        }
    };
    match app.current_tab {
        0 => app.scroll = apply(app.scroll, direction),
        2 => app.hourly_scroll = apply(app.hourly_scroll, direction),
        3 => app.raw_scroll = apply(app.raw_scroll, direction),
        _ => {}
    }
}

fn handle_events(app: &mut App) -> io::Result<()> {
    if let Event::Key(key) = event::read()? {
        if key.kind != KeyEventKind::Press {
            return Ok(());
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => app.running = false,
            KeyCode::Char('1') => app.current_tab = 0,
            KeyCode::Char('2') => app.current_tab = 1,
            KeyCode::Char('3') => app.current_tab = 2,
            KeyCode::Char('4') => app.current_tab = 3,
            KeyCode::Tab => app.current_tab = (app.current_tab + 1) % 4,
            KeyCode::BackTab => app.current_tab = (app.current_tab + 3) % 4,
            KeyCode::Left => handle_left_key(app),
            KeyCode::Right => handle_right_key(app),
            KeyCode::Up => {
                let step = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    3
                } else {
                    1
                };
                handle_scroll(app, step, -1);
            }
            KeyCode::Down => {
                let step = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    3
                } else {
                    1
                };
                handle_scroll(app, step, 1);
            }
            KeyCode::PageUp => {
                let step = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    30
                } else {
                    10
                };
                handle_scroll(app, step, -1);
            }
            KeyCode::PageDown => {
                let step = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    30
                } else {
                    10
                };
                handle_scroll(app, step, 1);
            }
            KeyCode::Enter if app.current_tab == 1 && !app.data.days.is_empty() => {
                let last = app.data.days.len().saturating_sub(1);
                let idx = app.selected_day_index.unwrap_or(last).min(last);
                app.selected_day_index = Some(idx);
                app.selected_hour = App::last_hour_for_day(&app.data.days[idx]);
                app.hourly_scroll = 0;
                app.current_tab = 2;
            }
            _ => {}
        }
    }
    Ok(())
}

fn ui(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas::<3>(frame.area());
    let [header_area, content_area, status_area] = chunks;

    render_header(frame, header_area, app);
    match app.current_tab {
        0 => tabs::overview::render_overview(frame, content_area, &app.data),
        1 => {
            let effective_idx = app
                .selected_day_index
                .unwrap_or(app.data.days.len().saturating_sub(1));
            tabs::daily_view::render_daily(frame, content_area, &app.data, effective_idx);
        }
        2 => tabs::hourly::render_hourly(frame, content_area, app),
        3 => tabs::raw::render_raw(frame, content_area, &app.entries, app.raw_scroll),
        _ => {}
    }
    render_status(frame, status_area, app);
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
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

fn render_status(frame: &mut Frame, area: Rect, _app: &App) {
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
