use std::collections::HashMap;

use chrono::NaiveDate;

use ufw_report::models::{
    build_aggregated, DailyReport, Direction, HourBreak, IpEntry, LogEntry, PortEntry,
};

fn entry(date: NaiveDate, hour: u32, ip: &str, port: Option<u16>, proto: &str) -> LogEntry {
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

#[test]
fn test_global_top_ips_aggregates_across_days() {
    let entries = vec![
        entry(
            NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            8,
            "10.0.0.1",
            Some(22),
            "TCP",
        ),
        entry(
            NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            9,
            "10.0.0.2",
            Some(80),
            "TCP",
        ),
        entry(
            NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            10,
            "10.0.0.1",
            Some(22),
            "TCP",
        ),
        entry(
            NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            11,
            "10.0.0.1",
            Some(443),
            "TCP",
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
            top_ips: vec![
                IpEntry {
                    ip: "10.0.0.1".into(),
                    count: 1,
                },
                IpEntry {
                    ip: "10.0.0.2".into(),
                    count: 1,
                },
            ],
            top_ports: vec![
                PortEntry { port: 22, count: 1 },
                PortEntry { port: 80, count: 1 },
            ],
            protocols: HashMap::from([("TCP".into(), 2)]),
        },
        DailyReport {
            date: NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            total_blocked: 2,
            hourly: vec![
                HourBreak { hour: 10, count: 1 },
                HourBreak { hour: 11, count: 1 },
            ],
            top_ips: vec![IpEntry {
                ip: "10.0.0.1".into(),
                count: 2,
            }],
            top_ports: vec![
                PortEntry { port: 22, count: 1 },
                PortEntry {
                    port: 443,
                    count: 1,
                },
            ],
            protocols: HashMap::from([("TCP".into(), 2)]),
        },
    ];

    let aggregated = build_aggregated(reports, &entries);

    // 10.0.0.1 aparece 3 veces en total
    assert!(!aggregated.top_ips.is_empty());
    assert_eq!(aggregated.top_ips[0].ip, "10.0.0.1");
    assert_eq!(aggregated.top_ips[0].count, 3);

    // total_blocked debe ser la suma de los daily reports
    assert_eq!(aggregated.total_blocked, 4);
}

#[test]
fn test_global_top_ports_from_all_entries() {
    let entries = vec![
        entry(
            NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            8,
            "10.0.0.1",
            Some(22),
            "TCP",
        ),
        entry(
            NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            9,
            "10.0.0.2",
            Some(80),
            "TCP",
        ),
        entry(
            NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            10,
            "10.0.0.1",
            Some(22),
            "TCP",
        ),
        entry(
            NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            11,
            "10.0.0.3",
            Some(22),
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
            top_ips: vec![
                IpEntry {
                    ip: "10.0.0.1".into(),
                    count: 1,
                },
                IpEntry {
                    ip: "10.0.0.2".into(),
                    count: 1,
                },
            ],
            top_ports: vec![
                PortEntry { port: 22, count: 1 },
                PortEntry { port: 80, count: 1 },
            ],
            protocols: HashMap::from([("TCP".into(), 2)]),
        },
        DailyReport {
            date: NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            total_blocked: 2,
            hourly: vec![
                HourBreak { hour: 10, count: 1 },
                HourBreak { hour: 11, count: 1 },
            ],
            top_ips: vec![
                IpEntry {
                    ip: "10.0.0.1".into(),
                    count: 1,
                },
                IpEntry {
                    ip: "10.0.0.3".into(),
                    count: 1,
                },
            ],
            top_ports: vec![
                PortEntry { port: 22, count: 1 },
                PortEntry { port: 80, count: 1 },
            ],
            protocols: HashMap::from([("TCP".into(), 1), ("UDP".into(), 1)]),
        },
    ];

    let aggregated = build_aggregated(reports, &entries);

    assert_eq!(aggregated.top_ports[0].port, 22);
    assert_eq!(aggregated.top_ports[0].count, 3);
}

#[test]
fn test_total_blocked_sum() {
    let entries = vec![
        entry(
            NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            8,
            "10.0.0.1",
            Some(22),
            "TCP",
        ),
        entry(
            NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            9,
            "10.0.0.2",
            Some(80),
            "TCP",
        ),
    ];

    let reports = vec![DailyReport {
        date: NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
        total_blocked: 2,
        hourly: vec![
            HourBreak { hour: 8, count: 1 },
            HourBreak { hour: 9, count: 1 },
        ],
        top_ips: vec![
            IpEntry {
                ip: "10.0.0.1".into(),
                count: 1,
            },
            IpEntry {
                ip: "10.0.0.2".into(),
                count: 1,
            },
        ],
        top_ports: vec![
            PortEntry { port: 22, count: 1 },
            PortEntry { port: 80, count: 1 },
        ],
        protocols: HashMap::from([("TCP".into(), 2)]),
    }];

    let aggregated = build_aggregated(reports, &entries);
    assert_eq!(aggregated.total_blocked, 2);
}

#[test]
fn test_aggregated_empty_entries() {
    let aggregated = build_aggregated(vec![], &[]);
    assert_eq!(aggregated.total_blocked, 0);
    assert!(aggregated.top_ips.is_empty());
    assert!(aggregated.top_ports.is_empty());
    assert!(aggregated.protocols.is_empty());
    assert!(aggregated.days.is_empty());
}

#[test]
fn test_protocols_merged() {
    let entries = vec![
        entry(
            NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            8,
            "10.0.0.1",
            Some(22),
            "TCP",
        ),
        entry(
            NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
            9,
            "10.0.0.2",
            Some(53),
            "UDP",
        ),
        entry(
            NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            10,
            "10.0.0.1",
            Some(22),
            "TCP",
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
            top_ips: vec![
                IpEntry {
                    ip: "10.0.0.1".into(),
                    count: 1,
                },
                IpEntry {
                    ip: "10.0.0.2".into(),
                    count: 1,
                },
            ],
            top_ports: vec![
                PortEntry { port: 22, count: 1 },
                PortEntry { port: 53, count: 1 },
            ],
            protocols: HashMap::from([("TCP".into(), 1), ("UDP".into(), 1)]),
        },
        DailyReport {
            date: NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            total_blocked: 1,
            hourly: vec![HourBreak { hour: 10, count: 1 }],
            top_ips: vec![IpEntry {
                ip: "10.0.0.1".into(),
                count: 1,
            }],
            top_ports: vec![PortEntry { port: 22, count: 1 }],
            protocols: HashMap::from([("TCP".into(), 1)]),
        },
    ];

    let aggregated = build_aggregated(reports, &entries);
    assert_eq!(aggregated.protocols.get("TCP"), Some(&2));
    assert_eq!(aggregated.protocols.get("UDP"), Some(&1));
}
