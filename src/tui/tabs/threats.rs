use crate::models::{Severity, ThreatReport};
use crate::tui::app::{App, ThreatsView};

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::Yellow,
        Severity::Medium => Color::Cyan,
        Severity::Low => Color::Gray,
    }
}

fn severity_style(severity: Severity, selected: bool) -> Style {
    let style = Style::default().fg(severity_color(severity));
    if selected {
        style.bg(Color::DarkGray).add_modifier(Modifier::BOLD)
    } else {
        style
    }
}

fn visible_window(len: usize, selection: usize, visible: usize) -> (usize, usize) {
    if len == 0 || visible == 0 {
        return (0, 0);
    }
    let selection = App::clamp_index(selection, len);
    let offset = selection
        .saturating_sub(visible.saturating_sub(1))
        .min(len.saturating_sub(visible));
    let end = (offset + visible).min(len);
    (offset, end)
}

fn render_summary(frame: &mut Frame, area: Rect, threat: &ThreatReport) {
    let summary = &threat.summary;
    let line = Line::from(vec![
        Span::styled(
            " Risk: ",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{} critical", summary.critical),
            Style::default().fg(Color::Red),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{} high", summary.high),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{} medium", summary.medium),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw("  "),
        Span::styled(
            format!("Findings: {}", summary.total_findings),
            Style::default().fg(Color::Magenta),
        ),
        Span::raw("  "),
        Span::styled(
            format!("Coverage: {:.1}%", threat.coverage.coverage_pct),
            Style::default().fg(Color::Green),
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_sources_table(frame: &mut Frame, area: Rect, threat: &ThreatReport, selection: usize) {
    let len = threat.profiles.len();
    let visible = usize::from(area.height.saturating_sub(3)).max(1);
    let (offset, end) = visible_window(len, selection, visible);
    let selected = App::clamp_index(selection, len);

    let rows: Vec<Row> = threat.profiles[offset..end]
        .iter()
        .enumerate()
        .map(|(position, profile)| {
            let index = offset + position;
            let tags = profile
                .findings
                .iter()
                .map(|kind| kind.short_label())
                .collect::<Vec<_>>()
                .join(",");
            Row::new(vec![
                Cell::from(format!("{}", index + 1)),
                Cell::from(profile.ip.clone()),
                Cell::from(format!("{}", profile.risk_score)),
                Cell::from(profile.severity.label()),
                Cell::from(if tags.is_empty() {
                    "-".to_string()
                } else {
                    tags
                }),
                Cell::from(profile.total_blocks.to_string()),
                Cell::from(profile.distinct_dst_ports.to_string()),
                Cell::from(profile.active_days.to_string()),
                Cell::from(profile.last_seen.to_string()),
            ])
            .style(severity_style(profile.severity, index == selected))
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Min(15),
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Length(7),
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(vec![
            "#", "IP", "Score", "Severity", "Tags", "Blocks", "Ports", "Days", "Last",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(format!(
        " {} ({} items)  [v] toggle ",
        ThreatsView::Sources.title(),
        len
    )));
    frame.render_widget(table, area);
}

fn render_networks_table(frame: &mut Frame, area: Rect, threat: &ThreatReport, selection: usize) {
    let len = threat.subnets.len();
    let visible = usize::from(area.height.saturating_sub(3)).max(1);
    let (offset, end) = visible_window(len, selection, visible);
    let selected = App::clamp_index(selection, len);

    let rows: Vec<Row> = threat.subnets[offset..end]
        .iter()
        .enumerate()
        .map(|(position, subnet)| {
            let index = offset + position;
            let selected = index == selected;
            let style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Cyan)
            };
            Row::new(vec![
                Cell::from(format!("{}", index + 1)),
                Cell::from(subnet.prefix.clone()),
                Cell::from(subnet.total_blocks.to_string()),
                Cell::from(subnet.distinct_sources.to_string()),
                Cell::from(subnet.distinct_ports.to_string()),
                Cell::from(subnet.last_seen.to_string()),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Min(18),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(vec!["#", "Prefix", "Blocks", "Sources", "Ports", "Last"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(format!(
        " {} ({} items)  [v] toggle ",
        ThreatsView::Networks.title(),
        len
    )));
    frame.render_widget(table, area);
}

fn source_detail_lines(profile: &crate::models::SourceProfile) -> Vec<Line<'static>> {
    let tags = profile
        .findings
        .iter()
        .map(|kind| kind.label())
        .collect::<Vec<_>>()
        .join(", ");
    let ports = profile
        .top_ports
        .iter()
        .map(|port| format!("{} ({})", port.port, port.count))
        .collect::<Vec<_>>()
        .join(", ");
    let protocols = profile
        .top_protocols
        .iter()
        .map(|(protocol, count)| format!("{protocol} ({count})"))
        .collect::<Vec<_>>()
        .join(", ");
    vec![
        Line::from(vec![
            Span::styled(
                format!(" {} ", profile.risk_score),
                severity_style(profile.severity, false).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{} ", profile.severity.label()),
                Style::default().fg(severity_color(profile.severity)),
            ),
            Span::raw(format!(
                "| Blocks {} | Ports {} | Days {} | Targets {}",
                profile.total_blocks,
                profile.distinct_dst_ports,
                profile.active_days,
                profile.distinct_dst_ips
            )),
        ]),
        Line::from(format!(
            "First seen {} | Last seen {} | Admin hits {}",
            profile.first_seen, profile.last_seen, profile.admin_port_hits
        )),
        Line::from(format!(
            "Tags: {}",
            if tags.is_empty() { "-" } else { &tags }
        )),
        Line::from(format!(
            "Top ports: {}",
            if ports.is_empty() { "-" } else { &ports }
        )),
        Line::from(format!(
            "Protocols: {}",
            if protocols.is_empty() {
                "-"
            } else {
                &protocols
            }
        )),
    ]
}

fn subnet_detail_lines(subnet: &crate::models::SubnetAggregate) -> Vec<Line<'static>> {
    let ports = subnet
        .top_ports
        .iter()
        .map(|port| format!("{} ({})", port.port, port.count))
        .collect::<Vec<_>>()
        .join(", ");
    vec![
        Line::from(vec![Span::styled(
            subnet.prefix.clone(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(format!(
            "Blocks {} | Sources {} | Ports {}",
            subnet.total_blocks, subnet.distinct_sources, subnet.distinct_ports
        )),
        Line::from(format!(
            "First seen {} | Last seen {}",
            subnet.first_seen, subnet.last_seen
        )),
        Line::from(format!(
            "Top ports: {}",
            if ports.is_empty() { "-" } else { &ports }
        )),
    ]
}

fn render_detail(
    frame: &mut Frame,
    area: Rect,
    threat: &ThreatReport,
    view: ThreatsView,
    selection: usize,
) {
    let block = Block::default().borders(Borders::ALL).title(" Details ");
    let lines = match view {
        ThreatsView::Sources => {
            let index = App::clamp_index(selection, threat.profiles.len());
            threat.profiles.get(index).map_or_else(
                || {
                    vec![Line::from(
                        "No sources above the minimum score. Coverage still applies.",
                    )]
                },
                source_detail_lines,
            )
        }
        ThreatsView::Networks => {
            let index = App::clamp_index(selection, threat.subnets.len());
            threat.subnets.get(index).map_or_else(
                || {
                    vec![Line::from(
                        "No network groups above the minimum source count.",
                    )]
                },
                subnet_detail_lines,
            )
        }
    };

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

pub(crate) fn render_threats(
    frame: &mut Frame,
    area: Rect,
    threat: &ThreatReport,
    view: ThreatsView,
    selection: usize,
) {
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(6),
        Constraint::Length(7),
    ])
    .areas::<3>(area);
    let [summary_area, table_area, detail_area] = chunks;

    render_summary(frame, summary_area, threat);
    match view {
        ThreatsView::Sources => render_sources_table(frame, table_area, threat, selection),
        ThreatsView::Networks => render_networks_table(frame, table_area, threat, selection),
    }
    render_detail(frame, detail_area, threat, view, selection);
}
