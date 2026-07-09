use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Direction {
    Incoming,
    Outgoing,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub date: NaiveDate,
    pub hour: u32,
    pub src_ip: String,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub direction: Direction,
}
