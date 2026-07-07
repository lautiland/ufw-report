use std::sync::LazyLock;

use chrono::NaiveDate;
use regex::Regex;

use crate::domain::LogEntry;

use super::date_utils::{normalize_protocol, parse_direction, parse_syslog_month, resolve_year};

static RE_SYSLOG_DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\w{3}\s+\d{1,2})\s+(\d{2}:\d{2}:\d{2})").unwrap());

static RE_ISO_DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d{4}-\d{2}-\d{2})T(\d{2}):\d{2}:\d{2}").unwrap());

static RE_SRC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"SRC=([0-9a-fA-F:.]+)").unwrap());

static RE_DPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"DPT=(\d+)").unwrap());

static RE_PROTO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"PROTO=(\w+)").unwrap());

static RE_DST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"DST=([0-9a-fA-F:.]+)").unwrap());

static RE_SPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"SPT=(\d+)").unwrap());

/// # Panics
///
/// Panics if the regex capture group index is out of bounds (should not happen with valid regex).
pub fn parse_log_line(line: &str, current_year: i32) -> Option<(NaiveDate, u32, LogEntry)> {
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
