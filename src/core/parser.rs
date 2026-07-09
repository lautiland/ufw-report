use std::sync::LazyLock;

use chrono::{Datelike, NaiveDate};
use regex::Regex;

use crate::models::{Direction, LogEntry};

static RE_SYSLOG_DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\w{3}\s+\d{1,2})\s+(\d{2}:\d{2}:\d{2})").unwrap());

static RE_ISO_DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d{4}-\d{2}-\d{2})T(\d{2}):\d{2}:\d{2}").unwrap());

static RE_SRC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"SRC=([0-9a-fA-F:.]+)").unwrap());

static RE_DPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"DPT=(\d+)").unwrap());

static RE_PROTO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"PROTO=(\w+)").unwrap());

static RE_DST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"DST=([0-9a-fA-F:.]+)").unwrap());

static RE_SPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"SPT=(\d+)").unwrap());

static RE_IN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bIN=(\S*)").unwrap());

static RE_OUT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bOUT=(\S*)").unwrap());

fn parse_syslog_month(abbr: &str) -> Option<u32> {
    match abbr {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

pub(crate) fn resolve_year(parsed_date: NaiveDate, current_year: i32) -> NaiveDate {
    let candidate = NaiveDate::from_ymd_opt(current_year, parsed_date.month(), parsed_date.day());
    match candidate {
        Some(d) if d > chrono::Local::now().date_naive() + chrono::TimeDelta::days(30) => {
            NaiveDate::from_ymd_opt(current_year - 1, parsed_date.month(), parsed_date.day())
                .unwrap_or(parsed_date)
        }
        Some(d) => d,
        None => parsed_date,
    }
}

pub(crate) fn normalize_protocol(raw: &str) -> String {
    match raw.to_uppercase().as_str() {
        "TCP" | "6" => "TCP".to_string(),
        "UDP" | "17" => "UDP".to_string(),
        "ICMP" | "1" => "ICMP".to_string(),
        "IGMP" | "2" => "IGMP".to_string(),
        "IPV6-ICMP" | "58" => "IPv6-ICMP".to_string(),
        "GRE" | "47" => "GRE".to_string(),
        "ESP" | "50" => "ESP".to_string(),
        "AH" | "51" => "AH".to_string(),
        "SCTP" | "132" => "SCTP".to_string(),
        other => other.to_string(),
    }
}

fn parse_direction(line: &str) -> Direction {
    let in_val = RE_IN
        .captures(line)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str());
    let out_val = RE_OUT
        .captures(line)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str());

    match (in_val, out_val) {
        (Some(in_iface), _) if !in_iface.is_empty() => Direction::Incoming,
        (_, Some(out_iface)) if !out_iface.is_empty() => Direction::Outgoing,
        _ => Direction::Unknown,
    }
}

pub(crate) fn parse_log_line(line: &str, current_year: i32) -> Option<(NaiveDate, u32, LogEntry)> {
    let line = line.trim();
    if !line.contains("[UFW BLOCK]") {
        return None;
    }

    let (date_str, hour) = if let Some(caps) = RE_ISO_DATE.captures(line) {
        let d = NaiveDate::parse_from_str(caps.get(1)?.as_str(), "%Y-%m-%d").ok()?;
        let h: u32 = caps.get(2)?.as_str().parse().ok()?;
        (d, h)
    } else if let Some(caps) = RE_SYSLOG_DATE.captures(line) {
        let date_part = caps.get(1)?.as_str();
        let time_part = caps.get(2)?.as_str();
        let h: u32 = time_part[..2].parse().ok()?;

        let mut parts = date_part.split_whitespace();
        let month_abbr = parts.next()?;
        let day_str = parts.next()?;
        let month = parse_syslog_month(month_abbr)?;
        let day: u32 = day_str.parse().ok()?;

        let d = NaiveDate::from_ymd_opt(current_year, month, day)?;
        let resolved = resolve_year(d, current_year);
        (resolved, h)
    } else {
        return None;
    };

    let src_ip = RE_SRC.captures(line)?.get(1)?.as_str().to_string();
    let dst_ip = RE_DST
        .captures(line)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string());
    let src_port = RE_SPT
        .captures(line)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<u16>().ok());
    let dst_port = RE_DPT
        .captures(line)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<u16>().ok());
    let protocol = RE_PROTO
        .captures(line)
        .map(|c| normalize_protocol(c.get(1).unwrap().as_str()));
    let direction = parse_direction(line);

    Some((
        date_str,
        hour,
        LogEntry {
            date: date_str,
            hour,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            direction,
        },
    ))
}

/// Public wrapper for testing. Parses a single UFW log line.
#[must_use]
pub fn parse_log_line_standalone(
    line: &str,
    current_year: i32,
) -> Option<(NaiveDate, u32, LogEntry)> {
    parse_log_line(line, current_year)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_syslog() {
        let line = "Jun 29 01:23:45 hostname kernel: [UFW BLOCK] IN=eth0 SRC=192.168.1.1 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";
        let result = parse_log_line(line, 2026);
        assert!(result.is_some());
        let (date, hour, entry) = result.unwrap();
        assert_eq!(date.to_string(), "2026-06-29");
        assert_eq!(hour, 1);
        assert_eq!(entry.src_ip, "192.168.1.1");
        assert_eq!(entry.dst_port, Some(22));
        assert_eq!(entry.protocol, Some("TCP".to_string()));
    }

    #[test]
    fn test_parse_ipv6_iso() {
        let line = "2026-06-29T14:30:00 hostname kernel: [UFW BLOCK] IN=eth0 SRC=2001:db8::1 DST=::1 PROTO=UDP SPT=123 DPT=53";
        let result = parse_log_line(line, 2026);
        assert!(result.is_some());
        let (date, hour, entry) = result.unwrap();
        assert_eq!(date.to_string(), "2026-06-29");
        assert_eq!(hour, 14);
        assert_eq!(entry.src_ip, "2001:db8::1");
        assert_eq!(entry.dst_port, Some(53));
        assert_eq!(entry.protocol, Some("UDP".to_string()));
    }

    #[test]
    fn test_skip_non_block() {
        let line = "Jun 29 01:23:45 hostname kernel: [UFW ALLOW] IN=eth0 SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP SPT=80 DPT=8080";
        assert!(parse_log_line(line, 2026).is_none());
    }

    #[test]
    fn test_skip_no_src() {
        let line = "Jun 29 01:23:45 hostname kernel: [UFW BLOCK] IN=eth0";
        assert!(parse_log_line(line, 2026).is_none());
    }

    #[test]
    fn test_parse_minimal_fields() {
        let line = "Jul  4 08:05:00 hostname kernel: [UFW BLOCK] SRC=10.0.0.1";
        let result = parse_log_line(line, 2026);
        assert!(result.is_some());
        let (_date, _hour, entry) = result.unwrap();
        assert_eq!(entry.src_ip, "10.0.0.1");
        assert!(entry.dst_port.is_none());
        assert!(entry.protocol.is_none());
    }

    #[test]
    fn test_hour_extraction() {
        let line = "2026-06-29T23:59:59 hostname kernel: [UFW BLOCK] SRC=10.0.0.1";
        let result = parse_log_line(line, 2026);
        assert!(result.is_some());
        let (_date, hour, _entry) = result.unwrap();
        assert_eq!(hour, 23);
    }

    #[test]
    fn test_syslog_single_digit_day() {
        let line = "Jul  4 08:05:00 hostname kernel: [UFW BLOCK] SRC=10.0.0.1 DPT=22 PROTO=TCP";
        let result = parse_log_line(line, 2026);
        assert!(result.is_some());
        let (date, hour, entry) = result.unwrap();
        assert_eq!(date.to_string(), "2026-07-04");
        assert_eq!(hour, 8);
        assert_eq!(entry.dst_port, Some(22));
    }

    #[test]
    fn test_fields_reordered() {
        let line = "Jun 29 01:23:45 hostname kernel: [UFW BLOCK] SRC=10.0.0.1 PROTO=TCP DPT=443";
        let result = parse_log_line(line, 2026);
        assert!(result.is_some());
        let (_date, _hour, entry) = result.unwrap();
        assert_eq!(entry.dst_port, Some(443));
        assert_eq!(entry.protocol, Some("TCP".to_string()));
    }

    #[test]
    fn test_resolve_year_rollover() {
        let today = NaiveDate::from_ymd_opt(2026, 1, 5).unwrap();
        let dec_log = NaiveDate::from_ymd_opt(2025, 12, 31).unwrap();
        let resolved = resolve_year(dec_log, today.year());
        assert_eq!(resolved.year(), 2025);
        assert_eq!(resolved, dec_log);
    }

    #[test]
    fn test_resolve_year_normal() {
        let today = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let jun_log = NaiveDate::from_ymd_opt(2026, 6, 15).unwrap();
        let resolved = resolve_year(jun_log, today.year());
        assert_eq!(resolved, jun_log);
    }
}
