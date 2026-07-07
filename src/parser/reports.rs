use std::collections::HashMap;

use chrono::NaiveDate;

use crate::domain::{DailyReport, HourBreak, IpEntry, LogEntry, PortEntry};

#[must_use]
pub fn build_daily_reports(
    entries: &[LogEntry],
    from: NaiveDate,
    to: NaiveDate,
) -> Vec<DailyReport> {
    let mut day_map: HashMap<NaiveDate, Vec<&LogEntry>> = HashMap::new();
    for entry in entries {
        day_map.entry(entry.date).or_default().push(entry);
    }

    let mut reports = Vec::new();
    let mut current = from;
    while current <= to {
        let day_entries = day_map.remove(&current).unwrap_or_default();
        let report = build_single_report(current, &day_entries);
        reports.push(report);
        current += chrono::Duration::days(1);
    }

    reports
}

fn build_single_report(date: NaiveDate, entries: &[&LogEntry]) -> DailyReport {
    let total_blocked = entries.len() as u64;

    let mut hourly_map: HashMap<u32, u64> = HashMap::new();
    let mut ip_map: HashMap<String, u64> = HashMap::new();
    let mut port_map: HashMap<u16, u64> = HashMap::new();
    let mut proto_map: HashMap<String, u64> = HashMap::new();

    for entry in entries {
        *hourly_map.entry(entry.hour).or_default() += 1;
        *ip_map.entry(entry.src_ip.clone()).or_default() += 1;
        if let Some(port) = entry.dst_port {
            *port_map.entry(port).or_default() += 1;
        }
        if let Some(ref proto) = entry.protocol {
            *proto_map.entry(proto.clone()).or_default() += 1;
        }
    }

    let mut hourly: Vec<HourBreak> = hourly_map
        .into_iter()
        .map(|(hour, count)| HourBreak { hour, count })
        .collect();
    hourly.sort_by_key(|h| h.hour);

    let mut top_ips: Vec<IpEntry> = ip_map
        .into_iter()
        .map(|(ip, count)| IpEntry { ip, count })
        .collect();
    top_ips.sort_by(|a, b| b.count.cmp(&a.count));
    top_ips.truncate(10);

    let mut top_ports: Vec<PortEntry> = port_map
        .into_iter()
        .map(|(port, count)| PortEntry { port, count })
        .collect();
    top_ports.sort_by(|a, b| b.count.cmp(&a.count));
    top_ports.truncate(10);

    DailyReport {
        date,
        total_blocked,
        hourly,
        top_ips,
        top_ports,
        protocols: proto_map,
    }
}
