use std::collections::HashMap;

use crate::models::PortEntry;

/// Sorts ports by count (descending) and then by port number, so the output is
/// deterministic across runs.
pub(crate) fn rank_ports(ports: &HashMap<u16, u64>, limit: usize) -> Vec<PortEntry> {
    let mut entries: Vec<PortEntry> = ports
        .iter()
        .map(|(port, count)| PortEntry {
            port: *port,
            count: *count,
        })
        .collect();
    entries.sort_by(|a, b| b.count.cmp(&a.count).then(a.port.cmp(&b.port)));
    entries.truncate(limit);
    entries
}

/// Sorts protocol counters by count (descending) and then by name.
pub(crate) fn rank_protocols(protocols: &HashMap<String, u64>, limit: usize) -> Vec<(String, u64)> {
    let mut entries: Vec<(String, u64)> = protocols
        .iter()
        .map(|(protocol, count)| (protocol.clone(), *count))
        .collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    entries.truncate(limit);
    entries
}
