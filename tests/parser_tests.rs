use chrono::NaiveDate;
use ufw_report::core::parser;
use ufw_report::models::Direction;

fn pl(line: &str) -> Option<(NaiveDate, u32, ufw_report::models::LogEntry)> {
    parser::parse_log_line_standalone(line, 2026)
}

#[test]
fn test_proto_numeric_tcp() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 PROTO=6 SPT=12345 DPT=80";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.protocol, Some("TCP".to_string()));
}

#[test]
fn test_proto_numeric_udp() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 PROTO=17 SPT=53 DPT=12345";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.protocol, Some("UDP".to_string()));
}

#[test]
fn test_proto_igmp() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.1 PROTO=2";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.protocol, Some("IGMP".to_string()));
}

#[test]
fn test_proto_icmp() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.1 PROTO=1";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.protocol, Some("ICMP".to_string()));
}

#[test]
fn test_proto_ipv6_icmp() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.1 PROTO=58";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.protocol, Some("IPv6-ICMP".to_string()));
}

#[test]
fn test_proto_gre() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.1 PROTO=47";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.protocol, Some("GRE".to_string()));
}

#[test]
fn test_proto_esp() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.1 PROTO=50";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.protocol, Some("ESP".to_string()));
}

#[test]
fn test_proto_sctp() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.1 PROTO=132";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.protocol, Some("SCTP".to_string()));
}

#[test]
fn test_proto_tcp_lowercase() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.1 PROTO=tcp";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.protocol, Some("TCP".to_string()));
}

#[test]
fn test_proto_unknown_numeric() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.1 PROTO=99";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.protocol, Some("99".to_string()));
}

#[test]
fn test_direction_incoming() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.1";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.direction, Direction::Incoming);
}

#[test]
fn test_direction_outgoing() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN= OUT=eth0 SRC=10.0.0.1";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.direction, Direction::Outgoing);
}

#[test]
fn test_direction_unknown() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] SRC=10.0.0.1";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.direction, Direction::Unknown);
}

#[test]
fn test_direction_in_out_empty() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN= OUT= SRC=10.0.0.1";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.direction, Direction::Unknown);
}

#[test]
fn test_dst_ip_captured() {
    let line =
        "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.dst_ip, Some("5.6.7.8".to_string()));
    assert_eq!(entry.src_ip, "1.2.3.4");
}

#[test]
fn test_dst_ip_missing() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=1.2.3.4";
    let entry = pl(line).unwrap().2;
    assert!(entry.dst_ip.is_none());
}

#[test]
fn test_src_port_captured() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=1.2.3.4 SPT=54321 DPT=80";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.src_port, Some(54321));
    assert_eq!(entry.dst_port, Some(80));
}

#[test]
fn test_src_port_missing() {
    let line = "Jun 29 01:23:45 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=1.2.3.4 DPT=80";
    let entry = pl(line).unwrap().2;
    assert!(entry.src_port.is_none());
    assert_eq!(entry.dst_port, Some(80));
}

#[test]
fn test_all_new_fields_incoming() {
    let line = "Jun 29 10:30:00 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=10.0.0.1 LEN=60 PROTO=6 SPT=33456 DPT=443";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.src_ip, "192.168.1.100");
    assert_eq!(entry.dst_ip, Some("10.0.0.1".to_string()));
    assert_eq!(entry.src_port, Some(33456));
    assert_eq!(entry.dst_port, Some(443));
    assert_eq!(entry.protocol, Some("TCP".to_string()));
    assert_eq!(entry.direction, Direction::Incoming);
}

#[test]
fn test_all_new_fields_outgoing() {
    let line = "Jun 29 10:30:00 host kernel: [UFW BLOCK] IN= OUT=eth0 MAC=... SRC=10.0.0.1 DST=192.168.1.100 LEN=60 PROTO=17 SPT=12345 DPT=53";
    let entry = pl(line).unwrap().2;
    assert_eq!(entry.src_ip, "10.0.0.1");
    assert_eq!(entry.dst_ip, Some("192.168.1.100".to_string()));
    assert_eq!(entry.src_port, Some(12345));
    assert_eq!(entry.dst_port, Some(53));
    assert_eq!(entry.protocol, Some("UDP".to_string()));
    assert_eq!(entry.direction, Direction::Outgoing);
}
