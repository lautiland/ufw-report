use crate::models::{AggregatedData, ThreatReport};

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table},
    Frame,
};

pub(crate) fn render_summary_cards(frame: &mut Frame, area: Rect, data: &AggregatedData) {
    let card_layout = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
    ]);
    let [total_area, incoming_area, outgoing_area, uniq_ip_area] = card_layout.areas(area);

    let total_card = Paragraph::new(Line::from(Span::styled(
        format!("{}", data.total_blocked),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Total Blocked "),
    );
    frame.render_widget(total_card, total_area);

    let in_card = Paragraph::new(Line::from(Span::styled(
        format!("{}", data.total_incoming),
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
    )))
    .block(Block::default().borders(Borders::ALL).title(" Incoming "));
    frame.render_widget(in_card, incoming_area);

    let out_card = Paragraph::new(Line::from(Span::styled(
        format!("{}", data.total_outgoing),
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    )))
    .block(Block::default().borders(Borders::ALL).title(" Outgoing "));
    frame.render_widget(out_card, outgoing_area);

    let unique_card = Paragraph::new(vec![
        Line::from(Span::styled(
            format!("{} total", data.unique_src_ips),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "v4 {} | v6 {}",
            data.unique_src_ips_v4, data.unique_src_ips_v6
        )),
    ])
    .block(Block::default().borders(Borders::ALL).title(" Unique IPs "));
    frame.render_widget(unique_card, uniq_ip_area);
}

fn to_u16_clamped(v: usize) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

pub(crate) fn render_protocol_gauges(
    frame: &mut Frame,
    area: Rect,
    data: &AggregatedData,
    scroll: usize,
) {
    let proto_total: u64 = data.protocols.values().sum();
    let mut sorted_protos: Vec<(&String, &u64)> = data.protocols.iter().collect();
    sorted_protos.sort_by(|a, b| b.1.cmp(a.1));

    let proto_inner = Block::default().borders(Borders::ALL).inner(area);
    let gauge_height = usize::from(proto_inner.height);
    let max_offset = sorted_protos.len().saturating_sub(gauge_height);
    let offset = scroll.min(max_offset);
    let visible_protos: Vec<_> = sorted_protos
        .iter()
        .skip(offset)
        .take(gauge_height)
        .collect();

    let title = if sorted_protos.len() > gauge_height && gauge_height > 0 {
        format!(
            " Protocols {}-{} of {} ",
            offset + 1,
            offset + visible_protos.len(),
            sorted_protos.len()
        )
    } else {
        " Protocols ".to_string()
    };
    frame.render_widget(Block::default().title(title).borders(Borders::ALL), area);

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

pub(crate) fn render_top_tables(frame: &mut Frame, area: Rect, data: &AggregatedData) {
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

fn render_risk_line(frame: &mut Frame, area: Rect, threat: &ThreatReport) {
    let summary = &threat.summary;
    let top = match (&summary.top_source, summary.top_score) {
        (Some(source), score) => format!("Top risk {score} ({source})"),
        (None, _) => "Top risk -".to_string(),
    };
    let line = Line::from(vec![
        Span::styled(
            " Threat ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            " {top} | {} critical | {} high | {} findings | coverage {:.1}%",
            summary.critical, summary.high, summary.total_findings, threat.coverage.coverage_pct
        )),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

pub(crate) fn render_overview(
    frame: &mut Frame,
    area: Rect,
    data: &AggregatedData,
    threat: &ThreatReport,
    scroll: usize,
) {
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(4),
        Constraint::Length(5),
        Constraint::Min(0),
    ])
    .areas::<4>(area);
    let [risk_area, cards_area, proto_area, tables_area] = chunks;

    render_risk_line(frame, risk_area, threat);
    render_summary_cards(frame, cards_area, data);
    render_protocol_gauges(frame, proto_area, data, scroll);
    render_top_tables(frame, tables_area, data);
}
