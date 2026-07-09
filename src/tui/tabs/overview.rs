use crate::models::AggregatedData;

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

fn to_u16_clamped(v: usize) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

pub(crate) fn render_protocol_gauges(frame: &mut Frame, area: Rect, data: &AggregatedData) {
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

pub(crate) fn render_overview(frame: &mut Frame, area: Rect, data: &AggregatedData) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(0),
    ])
    .areas::<3>(area);
    let [cards_area, proto_area, tables_area] = chunks;

    render_summary_cards(frame, cards_area, data);
    render_protocol_gauges(frame, proto_area, data);
    render_top_tables(frame, tables_area, data);
}
