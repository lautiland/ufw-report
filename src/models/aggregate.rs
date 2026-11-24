use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::entry::{Direction, LogEntry};
use super::report::{DailyReport, IpEntry, PortEntry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedData {
    pub days: Vec<DailyReport>,
    pub total_blocked: u64,
    pub total_incoming: u64,
    pub total_outgoing: u64,
    pub unique_src_ips: u64,
    pub unique_src_ips_v4: u64,
    pub unique_src_ips_v6: u64,
    pub top_ips: Vec<IpEntry>,
    pub top_ports: Vec<PortEntry>,
    pub protocols: HashMap<String, u64>,
}

#[must_use]
pub fn build_aggregated(reports: Vec<DailyReport>, all_entries: &[LogEntry]) -> AggregatedData {
    let total_blocked = reports.iter().map(|d| d.total_blocked).sum();

    let mut global_ips: HashMap<String, u64> = HashMap::new();
    let mut global_ports: HashMap<u16, u64> = HashMap::new();
    let mut global_protos: HashMap<String, u64> = HashMap::new();
    let mut unique_ips: HashSet<&str> = HashSet::new();
    let mut unique_ips_v4: HashSet<&str> = HashSet::new();
    let mut unique_ips_v6: HashSet<&str> = HashSet::new();
    let mut incoming: u64 = 0;
    let mut outgoing: u64 = 0;

    for entry in all_entries {
        *global_ips.entry(entry.src_ip.clone()).or_default() += 1;
        unique_ips.insert(entry.src_ip.as_str());
        match entry.src_ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => {
                unique_ips_v4.insert(entry.src_ip.as_str());
            }
            Ok(IpAddr::V6(_)) => {
                unique_ips_v6.insert(entry.src_ip.as_str());
            }
            Err(_) => {}
        }
        if let Some(port) = entry.dst_port {
            *global_ports.entry(port).or_default() += 1;
        }
        if let Some(ref proto) = entry.protocol {
            *global_protos.entry(proto.clone()).or_default() += 1;
        }
        match entry.direction {
            Direction::Incoming => incoming += 1,
            Direction::Outgoing => outgoing += 1,
            Direction::Unknown => {}
        }
    }

    let mut top_ips: Vec<IpEntry> = global_ips
        .into_iter()
        .map(|(ip, count)| IpEntry { ip, count })
        .collect();
    top_ips.sort_by_key(|b| std::cmp::Reverse(b.count));
    top_ips.truncate(10);

    let mut top_ports: Vec<PortEntry> = global_ports
        .into_iter()
        .map(|(port, count)| PortEntry { port, count })
        .collect();
    top_ports.sort_by_key(|b| std::cmp::Reverse(b.count));
    top_ports.truncate(10);

    AggregatedData {
        days: reports,
        total_blocked,
        total_incoming: incoming,
        total_outgoing: outgoing,
        unique_src_ips: unique_ips.len() as u64,
        unique_src_ips_v4: unique_ips_v4.len() as u64,
        unique_src_ips_v6: unique_ips_v6.len() as u64,
        top_ips,
        top_ports,
        protocols: global_protos,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn entry(ip: &str) -> LogEntry {
        let timestamp = NaiveDate::from_ymd_opt(2026, 6, 28)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .expect("test timestamp should be valid");
        let mut entry = LogEntry::new(timestamp, ip.to_string());
        entry.dst_port = Some(22);
        entry.protocol = Some("TCP".to_string());
        entry.direction = Direction::Incoming;
        entry
    }

    #[test]
    fn test_unique_ip_counts_are_not_truncated() {
        let mut entries: Vec<LogEntry> = (0..15).map(|i| entry(&format!("10.0.0.{i}"))).collect();
        entries.push(entry("2001:db8::1"));
        entries.push(entry("2001:db8::2"));

        let aggregated = build_aggregated(Vec::new(), &entries);

        assert_eq!(aggregated.top_ips.len(), 10);
        assert_eq!(aggregated.unique_src_ips, 17);
        assert_eq!(aggregated.unique_src_ips_v4, 15);
        assert_eq!(aggregated.unique_src_ips_v6, 2);
    }

    #[test]
    fn test_unique_ip_counts_deduplicate() {
        let entries = vec![entry("10.0.0.1"), entry("10.0.0.1"), entry("10.0.0.2")];

        let aggregated = build_aggregated(Vec::new(), &entries);

        assert_eq!(aggregated.unique_src_ips, 2);
        assert_eq!(aggregated.unique_src_ips_v4, 2);
        assert_eq!(aggregated.unique_src_ips_v6, 0);
    }
}
