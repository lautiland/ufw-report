use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;

use crate::models::{LogEntry, Severity, SourceProfile};

use super::util::{rank_ports, rank_protocols};

const TOP_PORTS: usize = 5;
const TOP_PROTOCOLS: usize = 5;

#[derive(Debug)]
struct ProfileAccumulator {
    total_blocks: u64,
    first_seen: NaiveDate,
    last_seen: NaiveDate,
    active_days: HashSet<NaiveDate>,
    ports: HashMap<u16, u64>,
    dst_ips: HashSet<String>,
    admin_port_hits: u64,
    protocols: HashMap<String, u64>,
}

impl ProfileAccumulator {
    fn new(date: NaiveDate) -> Self {
        Self {
            total_blocks: 0,
            first_seen: date,
            last_seen: date,
            active_days: HashSet::new(),
            ports: HashMap::new(),
            dst_ips: HashSet::new(),
            admin_port_hits: 0,
            protocols: HashMap::new(),
        }
    }

    fn observe(&mut self, entry: &LogEntry, admin_ports: &HashSet<u16>) {
        self.total_blocks += 1;
        if entry.date < self.first_seen {
            self.first_seen = entry.date;
        }
        if entry.date > self.last_seen {
            self.last_seen = entry.date;
        }
        self.active_days.insert(entry.date);

        if let Some(port) = entry.dst_port {
            *self.ports.entry(port).or_insert(0) += 1;
            if admin_ports.contains(&port) {
                self.admin_port_hits += 1;
            }
        }
        if let Some(dst_ip) = &entry.dst_ip {
            self.dst_ips.insert(dst_ip.clone());
        }
        if let Some(protocol) = &entry.protocol {
            *self.protocols.entry(protocol.clone()).or_insert(0) += 1;
        }
    }

    fn finish(self, ip: String) -> SourceProfile {
        SourceProfile {
            ip,
            total_blocks: self.total_blocks,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            active_days: u32::try_from(self.active_days.len()).unwrap_or(u32::MAX),
            distinct_dst_ports: u32::try_from(self.ports.len()).unwrap_or(u32::MAX),
            distinct_dst_ips: u32::try_from(self.dst_ips.len()).unwrap_or(u32::MAX),
            admin_port_hits: self.admin_port_hits,
            top_ports: rank_ports(&self.ports, TOP_PORTS),
            top_protocols: rank_protocols(&self.protocols, TOP_PROTOCOLS),
            findings: Vec::new(),
            risk_score: 0,
            severity: Severity::Low,
        }
    }
}

/// Builds one profile per source IP, sorted by volume (descending) and IP.
pub(crate) fn build_profiles(
    entries: &[LogEntry],
    admin_ports: &HashSet<u16>,
) -> Vec<SourceProfile> {
    let mut map: HashMap<&str, ProfileAccumulator> = HashMap::new();

    for entry in entries {
        let accumulator = map
            .entry(entry.src_ip.as_str())
            .or_insert_with(|| ProfileAccumulator::new(entry.date));
        accumulator.observe(entry, admin_ports);
    }

    let mut profiles: Vec<SourceProfile> = map
        .into_iter()
        .map(|(ip, accumulator)| accumulator.finish(ip.to_string()))
        .collect();
    profiles.sort_by(|a, b| {
        b.total_blocks
            .cmp(&a.total_blocks)
            .then_with(|| a.ip.cmp(&b.ip))
    });
    profiles
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Direction;

    fn entry(date: NaiveDate, hour: u32, ip: &str, dst_ip: Option<&str>, port: u16) -> LogEntry {
        LogEntry {
            date,
            hour,
            src_ip: ip.to_string(),
            dst_ip: dst_ip.map(std::string::ToString::to_string),
            src_port: None,
            dst_port: Some(port),
            protocol: Some("TCP".to_string()),
            direction: Direction::Incoming,
        }
    }

    #[test]
    fn test_profiles_aggregate_recurrence_and_ports() {
        let day1 = NaiveDate::from_ymd_opt(2026, 6, 28).unwrap();
        let day2 = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let day3 = NaiveDate::from_ymd_opt(2026, 6, 30).unwrap();
        let entries = vec![
            entry(day1, 8, "203.0.113.10", Some("192.168.1.1"), 22),
            entry(day1, 9, "203.0.113.10", Some("192.168.1.2"), 443),
            entry(day2, 10, "203.0.113.10", Some("192.168.1.1"), 22),
            entry(day3, 11, "203.0.113.10", Some("192.168.1.3"), 8080),
            entry(day3, 12, "198.51.100.20", None, 80),
        ];
        let admin = HashSet::from([22, 443, 8080]);

        let profiles = build_profiles(&entries, &admin);

        assert_eq!(profiles.len(), 2);
        let source = profiles
            .iter()
            .find(|profile| profile.ip == "203.0.113.10")
            .unwrap();
        assert_eq!(source.total_blocks, 4);
        assert_eq!(source.first_seen, day1);
        assert_eq!(source.last_seen, day3);
        assert_eq!(source.active_days, 3);
        assert_eq!(source.distinct_dst_ports, 3);
        assert_eq!(source.distinct_dst_ips, 3);
        assert_eq!(source.admin_port_hits, 4);
        assert_eq!(source.top_ports[0].port, 22);
        assert_eq!(source.top_ports[0].count, 2);
        assert_eq!(source.top_protocols[0], ("TCP".to_string(), 4));
    }

    #[test]
    fn test_profiles_are_sorted_by_volume_then_ip() {
        let day = NaiveDate::from_ymd_opt(2026, 6, 28).unwrap();
        let entries = vec![
            entry(day, 8, "10.0.0.2", None, 22),
            entry(day, 9, "10.0.0.1", None, 22),
            entry(day, 10, "10.0.0.1", None, 22),
        ];

        let profiles = build_profiles(&entries, &HashSet::new());

        assert_eq!(profiles[0].ip, "10.0.0.1");
        assert_eq!(profiles[1].ip, "10.0.0.2");
    }

    #[test]
    fn test_top_ports_break_ties_by_port_number() {
        let day = NaiveDate::from_ymd_opt(2026, 6, 28).unwrap();
        let entries = vec![
            entry(day, 8, "10.0.0.1", None, 443),
            entry(day, 9, "10.0.0.1", None, 22),
        ];

        let profiles = build_profiles(&entries, &HashSet::new());

        assert_eq!(profiles[0].top_ports[0].port, 22);
        assert_eq!(profiles[0].top_ports[1].port, 443);
    }
}
