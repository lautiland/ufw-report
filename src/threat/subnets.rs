use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use chrono::NaiveDate;
use ipnet::{Ipv4Net, Ipv6Net};

use crate::models::{LogEntry, SubnetAggregate};

use super::config::SubnetConfig;
use super::util::rank_ports;

const TOP_PORTS: usize = 5;

#[derive(Debug)]
struct SubnetAccumulator {
    total_blocks: u64,
    sources: HashSet<String>,
    ports: HashMap<u16, u64>,
    first_seen: NaiveDate,
    last_seen: NaiveDate,
}

impl SubnetAccumulator {
    fn new(date: NaiveDate) -> Self {
        Self {
            total_blocks: 0,
            sources: HashSet::new(),
            ports: HashMap::new(),
            first_seen: date,
            last_seen: date,
        }
    }

    fn observe(&mut self, entry: &LogEntry) {
        self.total_blocks += 1;
        self.sources.insert(entry.src_ip.clone());
        if let Some(port) = entry.dst_port {
            *self.ports.entry(port).or_insert(0) += 1;
        }
        if entry.date < self.first_seen {
            self.first_seen = entry.date;
        }
        if entry.date > self.last_seen {
            self.last_seen = entry.date;
        }
    }
}

fn prefix_for(ip: &str, config: &SubnetConfig) -> Option<String> {
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(address) => Ipv4Net::new(address, config.ipv4_prefix)
            .ok()
            .map(|net| net.trunc().to_string()),
        IpAddr::V6(address) => Ipv6Net::new(address, config.ipv6_prefix)
            .ok()
            .map(|net| net.trunc().to_string()),
    }
}

/// Groups sources into IPv4 `/n` and IPv6 `/n` prefixes.
///
/// Only prefixes with at least `min_sources` distinct sources are returned, so
/// a single noisy IP does not hide the botnets behind it.
pub(crate) fn build_subnets(
    entries: &[LogEntry],
    config: &SubnetConfig,
    min_sources: u32,
) -> Vec<SubnetAggregate> {
    let mut map: HashMap<String, SubnetAccumulator> = HashMap::new();

    for entry in entries {
        let Some(prefix) = prefix_for(&entry.src_ip, config) else {
            continue;
        };
        map.entry(prefix)
            .or_insert_with(|| SubnetAccumulator::new(entry.date))
            .observe(entry);
    }

    let mut subnets: Vec<SubnetAggregate> = map
        .into_iter()
        .filter(|(_, accumulator)| {
            u32::try_from(accumulator.sources.len()).unwrap_or(u32::MAX) >= min_sources
        })
        .map(|(prefix, accumulator)| SubnetAggregate {
            prefix,
            total_blocks: accumulator.total_blocks,
            distinct_sources: u32::try_from(accumulator.sources.len()).unwrap_or(u32::MAX),
            distinct_ports: u32::try_from(accumulator.ports.len()).unwrap_or(u32::MAX),
            top_ports: rank_ports(&accumulator.ports, TOP_PORTS),
            first_seen: accumulator.first_seen,
            last_seen: accumulator.last_seen,
        })
        .collect();
    subnets.sort_by(|a, b| {
        b.total_blocks
            .cmp(&a.total_blocks)
            .then_with(|| a.prefix.cmp(&b.prefix))
    });
    subnets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Direction;

    fn entry(date: NaiveDate, ip: &str, port: u16) -> LogEntry {
        let timestamp = date
            .and_hms_opt(10, 0, 0)
            .expect("test timestamp should be valid");
        let mut entry = LogEntry::new(timestamp, ip.to_string());
        entry.dst_ip = Some("192.168.1.1".to_string());
        entry.dst_port = Some(port);
        entry.protocol = Some("TCP".to_string());
        entry.direction = Direction::Incoming;
        entry
    }

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 6, 28).unwrap()
    }

    #[test]
    fn test_ipv4_groups_by_24() {
        let entries = vec![
            entry(day(), "203.0.113.10", 22),
            entry(day(), "203.0.113.11", 22),
            entry(day(), "198.51.100.5", 80),
        ];

        let subnets = build_subnets(&entries, &SubnetConfig::default(), 1);

        assert_eq!(subnets.len(), 2);
        let noisy = subnets
            .iter()
            .find(|subnet| subnet.prefix == "203.0.113.0/24")
            .unwrap();
        assert_eq!(noisy.total_blocks, 2);
        assert_eq!(noisy.distinct_sources, 2);
        assert_eq!(noisy.distinct_ports, 1);
        assert_eq!(noisy.top_ports[0].port, 22);
    }

    #[test]
    fn test_ipv6_groups_by_64() {
        let entries = vec![
            entry(day(), "2001:db8:0:1::1", 22),
            entry(day(), "2001:db8:0:1::2", 443),
            entry(day(), "2001:db8:0:2::1", 22),
        ];

        let subnets = build_subnets(&entries, &SubnetConfig::default(), 1);

        assert_eq!(subnets.len(), 2);
        let first = subnets
            .iter()
            .find(|subnet| subnet.prefix == "2001:db8:0:1::/64")
            .unwrap();
        assert_eq!(first.distinct_sources, 2);
        assert_eq!(first.total_blocks, 2);
    }

    #[test]
    fn test_min_sources_filter() {
        let entries = vec![
            entry(day(), "10.0.0.1", 22),
            entry(day(), "10.0.0.2", 22),
            entry(day(), "10.0.0.3", 22),
        ];

        let subnets = build_subnets(&entries, &SubnetConfig::default(), 3);
        assert_eq!(subnets.len(), 1);

        let subnets = build_subnets(&entries, &SubnetConfig::default(), 4);
        assert_eq!(subnets.len(), 0);
    }

    #[test]
    fn test_invalid_ips_are_ignored() {
        let entries = vec![entry(day(), "not-an-ip", 22)];

        let subnets = build_subnets(&entries, &SubnetConfig::default(), 1);
        assert_eq!(subnets.len(), 0);
    }
}
