use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::entry::{Direction, LogEntry};
use super::reports::{DailyReport, IpEntry, PortEntry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedData {
    pub days: Vec<DailyReport>,
    pub total_blocked: u64,
    pub total_incoming: u64,
    pub total_outgoing: u64,
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
    let mut incoming: u64 = 0;
    let mut outgoing: u64 = 0;

    for entry in all_entries {
        *global_ips.entry(entry.src_ip.clone()).or_default() += 1;
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
    top_ips.sort_by(|a, b| b.count.cmp(&a.count));
    top_ips.truncate(10);

    let mut top_ports: Vec<PortEntry> = global_ports
        .into_iter()
        .map(|(port, count)| PortEntry { port, count })
        .collect();
    top_ports.sort_by(|a, b| b.count.cmp(&a.count));
    top_ports.truncate(10);

    AggregatedData {
        days: reports,
        total_blocked,
        total_incoming: incoming,
        total_outgoing: outgoing,
        top_ips,
        top_ports,
        protocols: global_protos,
    }
}
