use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

use super::app::App;

#[allow(clippy::too_many_lines)]
pub fn handle_events(app: &mut App) -> io::Result<()> {
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
            KeyCode::Tab => {
                app.current_tab = (app.current_tab + 1) % 4;
            }
            KeyCode::BackTab => {
                app.current_tab = (app.current_tab + 3) % 4;
            }
            KeyCode::Left => match app.current_tab {
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
            },
            KeyCode::Right => match app.current_tab {
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
            },
            KeyCode::Up => {
                let step = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    3
                } else {
                    1
                };
                match app.current_tab {
                    0 => app.scroll = app.scroll.saturating_sub(step),
                    2 => app.hourly_scroll = app.hourly_scroll.saturating_sub(step),
                    3 => app.raw_scroll = app.raw_scroll.saturating_sub(step),
                    _ => {}
                }
            }
            KeyCode::Down => {
                let step = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    3
                } else {
                    1
                };
                match app.current_tab {
                    0 => app.scroll = app.scroll.saturating_add(step),
                    2 => app.hourly_scroll = app.hourly_scroll.saturating_add(step),
                    3 => app.raw_scroll = app.raw_scroll.saturating_add(step),
                    _ => {}
                }
            }
            KeyCode::PageUp => {
                let step = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    30
                } else {
                    10
                };
                match app.current_tab {
                    0 => app.scroll = app.scroll.saturating_sub(step),
                    2 => app.hourly_scroll = app.hourly_scroll.saturating_sub(step),
                    3 => app.raw_scroll = app.raw_scroll.saturating_sub(step),
                    _ => {}
                }
            }
            KeyCode::PageDown => {
                let step = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    30
                } else {
                    10
                };
                match app.current_tab {
                    0 => app.scroll = app.scroll.saturating_add(step),
                    2 => app.hourly_scroll = app.hourly_scroll.saturating_add(step),
                    3 => app.raw_scroll = app.raw_scroll.saturating_add(step),
                    _ => {}
                }
            }
            KeyCode::Enter => {
                if app.current_tab == 1 && !app.data.days.is_empty() {
                    let last = app.data.days.len().saturating_sub(1);
                    let idx = app.selected_day_index.unwrap_or(last).min(last);
                    app.selected_day_index = Some(idx);
                    app.selected_hour = App::last_hour_for_day(&app.data.days[idx]);
                    app.hourly_scroll = 0;
                    app.current_tab = 2;
                }
            }
            _ => {}
        }
    }
    Ok(())
}
