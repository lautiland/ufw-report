use std::collections::HashMap;
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
    widgets::{
        Bar, BarChart, Block, Borders, Cell, Gauge, Paragraph, Row, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Table,
    },
    Frame, Terminal,
};

use crate::models::{AggregatedData, DailyReport, Direction as UfwDirection, LogEntry};

const TAB_TITLES: &[&str] = &[" Overview ", " Daily ", " Hourly ", " Raw "];

fn to_u16_clamped(v: usize) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

pub struct App {
    pub data: AggregatedData,
    pub entries: Vec<LogEntry>,
    pub current_tab: usize,
    pub selected_day_index: Option<usize>,
    pub selected_hour: Option<u32>,
    pub scroll: usize,
    pub raw_scroll: usize,
    pub hourly_scroll: usize,
    pub running: bool,
}

impl App {
    #[must_use]
    pub fn new(data: AggregatedData, entries: Vec<LogEntry>) -> Self {
        Self {
            data,
            entries,
            current_tab: 0,
            selected_day_index: None,
            selected_hour: None,
            scroll: 0,
            raw_scroll: 0,
            hourly_scroll: 0,
            running: true,
        }
    }

    fn last_hour_for_day(day: &DailyReport) -> Option<u32> {
        day.hourly.iter().max_by_key(|h| h.hour).map(|h| h.hour)
    }

    fn prev_hour_with_data(day: &DailyReport, from_hour: u32) -> Option<u32> {
        day.hourly
            .iter()
            .filter(|h| h.count > 0 && h.hour < from_hour)
            .max_by_key(|h| h.hour)
            .map(|h| h.hour)
    }

    fn next_hour_with_data(day: &DailyReport, from_hour: u32) -> Option<u32> {
        day.hourly
            .iter()
            .filter(|h| h.count > 0 && h.hour > from_hour)
            .min_by_key(|h| h.hour)
            .map(|h| h.hour)
    }

    fn prev_day_with_data(days: &[DailyReport], from_idx: usize) -> Option<usize> {
        (0..from_idx).rev().find(|&i| days[i].total_blocked > 0)
    }

    fn next_day_with_data(days: &[DailyReport], from_idx: usize) -> Option<usize> {
        (from_idx + 1..days.len()).find(|&i| days[i].total_blocked > 0)
    }
}

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

fn render_summary_cards(frame: &mut Frame, area: Rect, data: &AggregatedData) {
    let card_layout = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
    ]);
    let [total_area, incoming_area, outgoing_area, uniq_ip_area] = card_layout.areas(area);

    let total_card = Paragraph::new(Line::from(vec![
        Span::raw("Total Blocked"),
        Span::raw(" ".repeat(5)),
        Span::styled(
            format!("{}", data.total_blocked),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(total_card, total_area);

    let in_card = Paragraph::new(Line::from(vec![
        Span::raw("Incoming"),
        Span::raw(" ".repeat(9)),
        Span::styled(
            format!("{}", data.total_incoming),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(in_card, incoming_area);

    let out_card = Paragraph::new(Line::from(vec![
        Span::raw("Outgoing"),
        Span::raw(" ".repeat(9)),
        Span::styled(
            format!("{}", data.total_outgoing),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(out_card, outgoing_area);

    let unique = format!("IPv4: {} | IPv6: {}", data.top_ips.len(), 0);
    let unique_card = Paragraph::new(Line::from(vec![
        Span::raw("Unique IPs"),
        Span::raw(" ".repeat(7)),
        Span::styled(
            unique,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(unique_card, uniq_ip_area);
}

fn render_protocol_gauges(frame: &mut Frame, area: Rect, data: &AggregatedData) {
    let proto_total: u64 = data.protocols.values().sum();
    let mut sorted_protos: Vec<(&String, &u64)> = data.protocols.iter().collect();
    sorted_protos.sort_by(|a, b| b.1.cmp(a.1));

    let proto_block = Block::default().title(" Protocols ").borders(Borders::ALL);
    let proto_inner = proto_block.inner(area);
    frame.render_widget(proto_block, area);

    let gauge_height = usize::from(proto_inner.height);
    let visible_protos: Vec<_> = sorted_protos.iter().take(gauge_height).collect();

    for (i, (proto, count)) in visible_protos.iter().enumerate() {
        let pct = count
            .saturating_mul(100)
            .checked_div(proto_total)
            .and_then(|v| u16::try_from(v.min(u64::from(u16::MAX))).ok())
            .unwrap_or(0);
        let row_area = Rect {
            x: proto_inner.x,
            y: proto_inner.y + to_u16_clamped(i),
            width: proto_inner.width,
            height: 1,
        };
        let gauge = Gauge::default()
            .percent(pct)
            .label(format!(" {proto}  {pct:3}%  ({count})"))
            .gauge_style(match proto.as_str() {
                "TCP" => Color::Blue,
                "UDP" => Color::Green,
                "ICMP" => Color::Yellow,
                "IGMP" => Color::Magenta,
                "IPv6-ICMP" => Color::Cyan,
                _ => Color::White,
            });
        frame.render_widget(gauge, row_area);
    }
}

fn render_top_tables(frame: &mut Frame, area: Rect, data: &AggregatedData) {
    let table_chunks = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .areas::<2>(area);
    let [ips_table_area, ports_table_area] = table_chunks;

    let ips_rows: Vec<Row> = data
        .top_ips
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            Row::new(vec![
                Cell::from(format!("{}", i + 1)),
                Cell::from(ip.ip.clone()),
                Cell::from(format!("{}", ip.count)),
            ])
        })
        .collect();

    let ips_table = Table::new(
        ips_rows,
        [
            Constraint::Length(4),
            Constraint::Min(10),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec!["#", "Source IP", "Count"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().title(" Top IPs ").borders(Borders::ALL))
    .column_highlight_style(Style::default().fg(Color::Yellow));
    frame.render_widget(ips_table, ips_table_area);

    let port_rows: Vec<Row> = data
        .top_ports
        .iter()
        .enumerate()
        .map(|(i, p)| {
            Row::new(vec![
                Cell::from(format!("{}", i + 1)),
                Cell::from(format!("{}", p.port)),
                Cell::from(format!("{}", p.count)),
            ])
        })
        .collect();

    let ports_table = Table::new(
        port_rows,
        [
            Constraint::Length(4),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec!["#", "Port", "Count"]).style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().title(" Top Ports ").borders(Borders::ALL));
    frame.render_widget(ports_table, ports_table_area);
}

struct DailyBarsResult {
    bars: Vec<Bar<'static>>,
    offset: usize,
    max_count: u64,
    bar_width: usize,
    gap: usize,
    show_all: bool,
    num_days: usize,
    bars_per_width: usize,
}

fn build_daily_bars(
    data: &AggregatedData,
    effective_idx: usize,
    area_width: u16,
) -> DailyBarsResult {
    let num_days = data.days.len();
    let avail = (area_width as usize).saturating_sub(2);
    let gap = 1usize;
    let total_gaps = num_days.saturating_sub(1) * gap;

    let bar_width = if avail > total_gaps {
        ((avail - total_gaps) / num_days).clamp(1, 12)
    } else {
        1usize
    };

    let bars_per_width = avail / (bar_width + gap);
    let show_all = bars_per_width >= num_days;

    if show_all {
        let max_count = data
            .days
            .iter()
            .map(|d| d.total_blocked)
            .max()
            .unwrap_or(1)
            .max(1);
        let bars = data
            .days
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let style = if i == effective_idx {
                    Style::default().fg(Color::Yellow).bg(Color::DarkGray)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                Bar::with_label(d.date.format("%m/%d").to_string(), d.total_blocked).style(style)
            })
            .collect();
        DailyBarsResult {
            bars,
            offset: 0,
            max_count,
            bar_width,
            gap,
            show_all: true,
            num_days,
            bars_per_width,
        }
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
        let bars = data.days[offset..end]
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let global_i = offset + i;
                let style = if global_i == effective_idx {
                    Style::default().fg(Color::Yellow).bg(Color::DarkGray)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                Bar::with_label(d.date.format("%m/%d").to_string(), d.total_blocked).style(style)
            })
            .collect();
        DailyBarsResult {
            bars,
            offset,
            max_count,
            bar_width,
            gap,
            show_all: false,
            num_days,
            bars_per_width,
        }
    }
}

fn build_hourly_bars(day: &DailyReport, effective_hour: u32) -> Vec<Bar<'static>> {
    let mut hourly_map: HashMap<u32, u64> = HashMap::new();
    for h in &day.hourly {
        hourly_map.insert(h.hour, h.count);
    }

    (0..24)
        .map(|hour| {
            let count = hourly_map.get(&hour).copied().unwrap_or(0);
            let label = format!("{hour:02}");
            let style = if hour == effective_hour {
                Style::default().fg(Color::Yellow)
            } else if count > 0 {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            Bar::with_label(label, count).style(style)
        })
        .collect()
}

fn render_hourly_log_table(frame: &mut Frame, area: Rect, entries: &[&LogEntry], scroll: usize) {
    let max_visible = (area.height as usize).saturating_sub(3).max(1);

    let rows: Vec<Row> = entries
        .iter()
        .skip(scroll)
        .take(max_visible)
        .map(|e| {
            let port = e.dst_port.map_or("-".to_string(), |p| p.to_string());
            Row::new(vec![
                Cell::from(if e.src_ip.len() > 18 {
                    format!("{}..", &e.src_ip[..18])
                } else {
                    e.src_ip.clone()
                }),
                Cell::from(e.dst_ip.as_deref().unwrap_or("-").to_string()),
                Cell::from(e.protocol.as_deref().unwrap_or("-").to_string()),
                Cell::from(port),
                Cell::from(match e.direction {
                    UfwDirection::Incoming => "IN",
                    UfwDirection::Outgoing => "OUT",
                    UfwDirection::Unknown => "?",
                }),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(20),
        Constraint::Length(20),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(4),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["Src IP", "Dst IP", "Proto", "Port", "Dir"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .title(format!(" Logs ({} entries) ", entries.len()))
                .borders(Borders::ALL),
        );

    frame.render_widget(table, area);

    if entries.len() > max_visible {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        let mut state =
            ScrollbarState::new(entries.len().saturating_sub(max_visible)).position(scroll);
        frame.render_stateful_widget(scrollbar, area, &mut state);
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
        0 => render_overview(frame, content_area, app),
        1 => render_daily(frame, content_area, app),
        2 => render_hourly(frame, content_area, app),
        3 => render_raw(frame, content_area, app),
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

fn render_overview(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(0),
    ])
    .areas::<3>(area);
    let [cards_area, proto_area, tables_area] = chunks;

    render_summary_cards(frame, cards_area, &app.data);
    render_protocol_gauges(frame, proto_area, &app.data);
    render_top_tables(frame, tables_area, &app.data);
}

fn render_daily(frame: &mut Frame, area: Rect, app: &App) {
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
        .unwrap_or(data.days.len().saturating_sub(1));

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

fn render_hourly(frame: &mut Frame, area: Rect, app: &App) {
    let data = &app.data;

    if data.days.is_empty() {
        let msg = Paragraph::new("No day selected — go to Daily tab and press Enter")
            .block(Block::default().borders(Borders::ALL).title(" Hourly "))
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(msg, area);
        return;
    }

    let day_idx = app
        .selected_day_index
        .unwrap_or(data.days.len().saturating_sub(1))
        .min(data.days.len().saturating_sub(1));
    let day = &data.days[day_idx];

    let effective_hour = app
        .selected_hour
        .or_else(|| App::last_hour_for_day(day))
        .unwrap_or(0)
        .min(23);

    let num_hours = 24usize;
    let avail = (area.width as usize).saturating_sub(2);
    let gap = 1usize;
    let total_gaps = num_hours.saturating_sub(1) * gap;

    let bar_width = if avail > total_gaps {
        ((avail - total_gaps) / num_hours).clamp(1, 6)
    } else {
        1usize
    };

    let max_count = day.hourly.iter().map(|h| h.count).max().unwrap_or(1).max(1);
    let bars = build_hourly_bars(day, effective_hour);

    let hourly_entries: Vec<&LogEntry> = app
        .entries
        .iter()
        .filter(|e| e.date == day.date && e.hour == effective_hour)
        .collect();

    let bar_area_height = if hourly_entries.is_empty() { 5 } else { 7 };

    let chunks = Layout::vertical([Constraint::Length(bar_area_height), Constraint::Min(0)])
        .areas::<2>(area);
    let [chart_area, entries_area] = chunks;

    let chart = BarChart::new(bars)
        .block(
            Block::default()
                .title(format!(
                    " Hourly: {}  (↑↓ hour {:02}:00, ←→ day) ",
                    day.date, effective_hour
                ))
                .borders(Borders::ALL),
        )
        .max(max_count)
        .bar_width(to_u16_clamped(bar_width))
        .bar_gap(to_u16_clamped(gap));

    frame.render_widget(chart, chart_area);

    if hourly_entries.is_empty() {
        let msg = Paragraph::new("No entries for this hour")
            .block(Block::default().borders(Borders::ALL).title(" Logs "))
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(msg, entries_area);
        return;
    }

    let max_visible = (entries_area.height as usize).saturating_sub(3).max(1);
    let max_scroll = hourly_entries.len().saturating_sub(max_visible);
    let scroll = app.hourly_scroll.min(max_scroll);

    render_hourly_log_table(frame, entries_area, &hourly_entries, scroll);
}

fn render_raw(frame: &mut Frame, area: Rect, app: &App) {
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
