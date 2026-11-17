pub mod app;
pub mod tabs;
pub mod widgets;

use std::io;
use std::sync::{Arc, Mutex};

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

use self::app::{App, Tab};

type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send + 'static>;

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = io::stdout().execute(LeaveAlternateScreen);
}

/// # Errors
///
/// Returns an error if the terminal cannot be initialized or events fail to read.
pub fn run_tui(data: AggregatedData, entries: Vec<LogEntry>) -> anyhow::Result<()> {
    let original_hook: Arc<Mutex<Option<PanicHook>>> =
        Arc::new(Mutex::new(Some(std::panic::take_hook())));
    let hook_for_panic = Arc::clone(&original_hook);
    std::panic::set_hook(Box::new(move |panic_info| {
        restore_terminal();
        if let Ok(guard) = hook_for_panic.lock() {
            if let Some(hook) = guard.as_ref() {
                hook(panic_info);
            }
        }
    }));

    let result = run_tui_inner(data, entries);

    let _ = std::panic::take_hook();
    if let Ok(mut guard) = original_hook.lock() {
        if let Some(hook) = guard.take() {
            std::panic::set_hook(hook);
        }
    }

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

fn set_tab(app: &mut App, tab: Tab) {
    if app.current_tab != tab {
        app.current_tab = tab;
        app.hourly_scroll = 0;
    }
}

fn current_day_index(app: &App) -> Option<usize> {
    if app.data.days.is_empty() {
        return None;
    }
    let last = app.data.days.len() - 1;
    Some(app.selected_day_index.unwrap_or(last).min(last))
}

fn move_day(app: &mut App, forward: bool) {
    let Some(idx) = current_day_index(app) else {
        return;
    };
    let target = if forward {
        App::next_day_with_data(&app.data.days, idx)
    } else {
        App::prev_day_with_data(&app.data.days, idx)
    };
    let Some(target) = target else {
        return;
    };
    app.selected_day_index = Some(target);
    app.selected_hour = App::last_hour_for_day(&app.data.days[target]);
    app.hourly_scroll = 0;
}

fn move_hour(app: &mut App, forward: bool) {
    let Some(idx) = current_day_index(app) else {
        return;
    };
    let day = &app.data.days[idx];
    let current = app
        .selected_hour
        .or_else(|| App::last_hour_for_day(day))
        .unwrap_or(0)
        .min(23);
    let target = if forward {
        App::next_hour_with_data(day, current)
    } else {
        App::prev_hour_with_data(day, current)
    };
    if let Some(hour) = target {
        app.selected_day_index = Some(idx);
        app.selected_hour = Some(hour);
        app.hourly_scroll = 0;
    }
}

fn apply_scroll(current: usize, step: usize, direction: i8) -> usize {
    if direction > 0 {
        current.saturating_add(step)
    } else {
        current.saturating_sub(step)
    }
}

fn overview_scroll_limit(app: &App) -> usize {
    app.data.protocols.len().saturating_sub(1)
}

fn handle_vertical(app: &mut App, step: usize, direction: i8) {
    match app.current_tab {
        Tab::Overview => {
            app.scroll = apply_scroll(app.scroll, step, direction).min(overview_scroll_limit(app));
        }
        Tab::Hourly => move_hour(app, direction > 0),
        Tab::Raw => app.raw_scroll = apply_scroll(app.raw_scroll, step, direction),
        Tab::Daily => {}
    }
}

fn handle_page(app: &mut App, step: usize, direction: i8) {
    match app.current_tab {
        Tab::Overview => {
            app.scroll = apply_scroll(app.scroll, step, direction).min(overview_scroll_limit(app));
        }
        Tab::Hourly => app.hourly_scroll = apply_scroll(app.hourly_scroll, step, direction),
        Tab::Raw => app.raw_scroll = apply_scroll(app.raw_scroll, step, direction),
        Tab::Daily => {}
    }
}

fn handle_events(app: &mut App) -> io::Result<()> {
    if let Event::Key(key) = event::read()? {
        if key.kind != KeyEventKind::Press {
            return Ok(());
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => app.running = false,
            KeyCode::Char('1') => set_tab(app, Tab::Overview),
            KeyCode::Char('2') => set_tab(app, Tab::Daily),
            KeyCode::Char('3') => set_tab(app, Tab::Hourly),
            KeyCode::Char('4') => set_tab(app, Tab::Raw),
            KeyCode::Tab => set_tab(app, app.current_tab.next()),
            KeyCode::BackTab => set_tab(app, app.current_tab.prev()),
            KeyCode::Left => {
                if matches!(app.current_tab, Tab::Daily | Tab::Hourly) {
                    move_day(app, false);
                }
            }
            KeyCode::Right => {
                if matches!(app.current_tab, Tab::Daily | Tab::Hourly) {
                    move_day(app, true);
                }
            }
            KeyCode::Up => {
                let step = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    3
                } else {
                    1
                };
                handle_vertical(app, step, -1);
            }
            KeyCode::Down => {
                let step = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    3
                } else {
                    1
                };
                handle_vertical(app, step, 1);
            }
            KeyCode::PageUp => {
                let step = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    30
                } else {
                    10
                };
                handle_page(app, step, -1);
            }
            KeyCode::PageDown => {
                let step = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    30
                } else {
                    10
                };
                handle_page(app, step, 1);
            }
            KeyCode::Enter if app.current_tab == Tab::Daily && !app.data.days.is_empty() => {
                if let Some(idx) = current_day_index(app) {
                    app.selected_day_index = Some(idx);
                    app.selected_hour = App::last_hour_for_day(&app.data.days[idx]);
                    app.hourly_scroll = 0;
                    set_tab(app, Tab::Hourly);
                }
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
        Tab::Overview => {
            tabs::overview::render_overview(frame, content_area, &app.data, app.scroll);
        }
        Tab::Daily => {
            let last = app.data.days.len().saturating_sub(1);
            let effective_idx = app.selected_day_index.unwrap_or(last).min(last);
            tabs::daily::render_daily(frame, content_area, &app.data, effective_idx);
        }
        Tab::Hourly => tabs::hourly::render_hourly(frame, content_area, app),
        Tab::Raw => tabs::raw::render_raw(frame, content_area, &app.entries, app.raw_scroll),
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
    for tab in Tab::ALL {
        let style = if tab == app.current_tab {
            Style::default()
                .fg(Color::Black)
                .bg(Color::LightYellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White).bg(Color::DarkGray)
        };
        tab_spans.push(Span::styled(format!(" {} ", tab.title()), style));
    }

    let header = Paragraph::new(Line::from(tab_spans));
    frame.render_widget(header, area);
}

fn render_status(frame: &mut Frame, area: Rect, app: &App) {
    let text = Line::from(vec![
        Span::styled("[Tab]", Style::default().fg(Color::Cyan)),
        Span::raw(" Switch "),
        Span::raw(app.current_tab.hint()),
        Span::raw("  "),
        Span::styled("[q]", Style::default().fg(Color::Cyan)),
        Span::raw(" Quit"),
    ]);
    let status = Paragraph::new(text).style(Style::default().bg(Color::DarkGray).fg(Color::White));
    frame.render_widget(status, area);
}
