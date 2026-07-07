use std::collections::HashMap;

use chrono::NaiveDate;

use ufw_report::domain::{DailyReport, Direction, HourBreak, IpEntry, LogEntry, PortEntry};
use ufw_report::output;

fn make_entry(date: NaiveDate, hour: u32, ip: &str, port: Option<u16>, proto: &str) -> LogEntry {
    LogEntry {
        date,
        hour,
        src_ip: ip.to_string(),
        dst_ip: None,
        src_port: None,
        dst_port: port,
        protocol: Some(proto.to_string()),
        direction: Direction::Incoming,
    }
}

fn sample_entries() -> Vec<LogEntry> {
    vec![
        make_entry(
            NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            8,
            "10.0.0.1",
            Some(22),
            "TCP",
        ),
        make_entry(
            NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            14,
            "10.0.0.2",
            Some(80),
            "UDP",
        ),
        make_entry(
            NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            22,
            "10.0.0.3",
            Some(443),
            "TCP",
        ),
    ]
}

#[test]
fn test_write_csv_to_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.csv");
    let path_str = path.to_str().unwrap();

    output::write_output(&sample_entries(), path_str).unwrap();

    let contents = std::fs::read_to_string(path_str).unwrap();
    assert!(contents.starts_with("date,hour,src_ip,dst_ip,src_port,dst_port,protocol,direction\n"));
    assert!(contents.contains("2026-06-28,8,10.0.0.1,,,22,TCP,in"));
    assert!(contents.contains("2026-06-29,22,10.0.0.3,,,443,TCP,in"));
    assert_eq!(contents.lines().count(), 4);
}

#[test]
fn test_write_json_to_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.json");
    let path_str = path.to_str().unwrap();

    output::write_output(&sample_entries(), path_str).unwrap();

    let contents = std::fs::read_to_string(path_str).unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&contents).unwrap();
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed[0]["src_ip"], "10.0.0.1");
    assert_eq!(parsed[1]["dst_port"], 80);
    assert_eq!(parsed[2]["src_ip"], "10.0.0.3");
}

#[test]
fn test_write_json_default_extension() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report"); // no extension → defaults to JSON
    let path_str = path.to_str().unwrap();

    output::write_output(&sample_entries(), path_str).unwrap();

    let contents = std::fs::read_to_string(path_str).unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&contents).unwrap();
    assert_eq!(parsed.len(), 3);
}

#[test]
fn test_write_stdout_flag() {
    let mut buf = Vec::new();
    output::write_json(&mut buf, &sample_entries()).unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_slice(&buf).unwrap();
    assert_eq!(parsed.len(), 3);
}

#[test]
fn test_csv_all_fields_present() {
    let entries = vec![LogEntry {
        date: NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
        hour: 8,
        src_ip: "192.168.1.100".to_string(),
        dst_ip: Some("10.0.0.1".to_string()),
        src_port: Some(33456),
        dst_port: Some(443),
        protocol: Some("TCP".to_string()),
        direction: Direction::Outgoing,
    }];

    let mut buf = Vec::new();
    output::write_csv(&mut buf, &entries).unwrap();
    let output = String::from_utf8(buf).unwrap();

    assert!(output.contains("192.168.1.100"));
    assert!(output.contains("10.0.0.1"));
    assert!(output.contains("33456"));
    assert!(output.contains("443"));
    assert!(output.contains("TCP"));
    assert!(output.contains("out"));
}

#[test]
fn test_build_aggregated_consistency() {
    let entries = vec![
        make_entry(
            NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            8,
            "10.0.0.1",
            Some(22),
            "TCP",
        ),
        make_entry(
            NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            9,
            "10.0.0.1",
            Some(22),
            "TCP",
        ),
        make_entry(
            NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            10,
            "10.0.0.2",
            Some(80),
            "UDP",
        ),
    ];

    let reports = vec![
        DailyReport {
            date: NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            total_blocked: 2,
            hourly: vec![
                HourBreak { hour: 8, count: 1 },
                HourBreak { hour: 9, count: 1 },
            ],
            top_ips: vec![IpEntry {
                ip: "10.0.0.1".into(),
                count: 2,
            }],
            top_ports: vec![PortEntry { port: 22, count: 2 }],
            protocols: HashMap::from([("TCP".into(), 2)]),
        },
        DailyReport {
            date: NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            total_blocked: 1,
            hourly: vec![HourBreak { hour: 10, count: 1 }],
            top_ips: vec![IpEntry {
                ip: "10.0.0.2".into(),
                count: 1,
            }],
            top_ports: vec![PortEntry { port: 80, count: 1 }],
            protocols: HashMap::from([("UDP".into(), 1)]),
        },
    ];

    let aggregated = ufw_report::domain::build_aggregated(reports, &entries);
    assert_eq!(aggregated.total_blocked, 3);
    assert_eq!(aggregated.total_incoming, 3);
    assert_eq!(aggregated.top_ips[0].ip, "10.0.0.1");
    assert_eq!(aggregated.top_ips[0].count, 2);
    assert_eq!(aggregated.protocols.get("TCP"), Some(&2));
    assert_eq!(aggregated.protocols.get("UDP"), Some(&1));
}
