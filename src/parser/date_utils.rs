use std::sync::LazyLock;

use chrono::{Datelike, NaiveDate};

use crate::domain::Direction;

static RE_IN: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\bIN=(\S*)").unwrap());

static RE_OUT: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\bOUT=(\S*)").unwrap());

#[must_use]
pub fn parse_syslog_month(abbr: &str) -> Option<u32> {
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

#[must_use]
pub fn resolve_year(parsed_date: NaiveDate, current_year: i32) -> NaiveDate {
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

#[must_use]
pub fn normalize_protocol(raw: &str) -> String {
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

pub fn parse_direction(line: &str) -> Direction {
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
