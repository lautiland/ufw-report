mod app;
mod daily;
mod events;
mod header;
mod hourly;
mod overview;
mod raw;
mod status;

use std::io;

use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    Terminal,
};

use crate::domain::{AggregatedData, LogEntry};

use self::app::App;
use self::events::handle_events;
use self::header::render_header;
use self::hourly::render_hourly;
use self::overview::render_overview;
use self::raw::render_raw;
use self::status::render_status;

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = io::stdout().execute(LeaveAlternateScreen);
}

/// # Errors
///
/// Returns an error if the terminal setup or event handling fails.
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
        terminal.draw(|frame| {
            let chunks = Layout::vertical([
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .areas::<3>(frame.area());
            let [header_area, content_area, status_area] = chunks;

            render_header(frame, header_area, &app);
            match app.current_tab {
                0 => render_overview(frame, content_area, &app),
                1 => daily::render_daily(frame, content_area, &app),
                2 => render_hourly(frame, content_area, &app),
                3 => render_raw(frame, content_area, &app),
                _ => {}
            }
            render_status(frame, status_area, &app);
        })?;
        handle_events(&mut app)?;
    }

    restore_terminal();
    Ok(())
}
