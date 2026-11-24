use chrono::{NaiveDate, NaiveDateTime, Timelike};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Direction {
    Incoming,
    Outgoing,
    Unknown,
}

/// A single blocked packet.
///
/// `timestamp` is the authoritative time of the event. `date` and `hour` are
/// kept in sync for the existing CSV/JSON schema and for hourly aggregation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogEntry {
    pub timestamp: NaiveDateTime,
    pub date: NaiveDate,
    pub hour: u32,
    pub src_ip: String,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub direction: Direction,
}

impl LogEntry {
    /// Builds an entry from its authoritative timestamp.
    ///
    /// The `date` and `hour` fields are derived here so they can never drift
    /// from `timestamp` when entries are created in code.
    #[must_use]
    pub fn new(timestamp: NaiveDateTime, src_ip: String) -> Self {
        Self {
            timestamp,
            date: timestamp.date(),
            hour: timestamp.hour(),
            src_ip,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            protocol: None,
            direction: Direction::Unknown,
        }
    }

    /// Returns `true` when the derived date and hour match the timestamp.
    ///
    /// Cache entries are validated with this check before they are trusted.
    #[must_use]
    pub fn has_consistent_time(&self) -> bool {
        self.date == self.timestamp.date() && self.hour == self.timestamp.hour()
    }
}
