use std::io::Write;

use crate::models::{Direction, LogEntry};

/// # Errors
///
/// Returns an error if writing to the writer fails.
pub fn write_csv<W: Write>(mut writer: W, entries: &[LogEntry]) -> anyhow::Result<()> {
    writeln!(
        writer,
        "date,hour,src_ip,dst_ip,src_port,dst_port,protocol,direction"
    )?;
    for e in entries {
        writeln!(
            writer,
            "{},{},{},{},{},{},{},{}",
            e.date.format("%Y-%m-%d"),
            e.hour,
            e.src_ip,
            e.dst_ip.as_deref().unwrap_or(""),
            e.src_port.map_or(String::new(), |p| p.to_string()),
            e.dst_port.map_or(String::new(), |p| p.to_string()),
            e.protocol.as_deref().unwrap_or(""),
            match e.direction {
                Direction::Incoming => "in",
                Direction::Outgoing => "out",
                Direction::Unknown => "?",
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn sample_entries() -> Vec<LogEntry> {
        vec![
            LogEntry {
                date: NaiveDate::from_ymd_opt(2026, 6, 28).unwrap(),
                hour: 8,
                src_ip: "10.0.0.1".to_string(),
                dst_ip: Some("192.168.1.1".to_string()),
                src_port: Some(54321),
                dst_port: Some(22),
                protocol: Some("TCP".to_string()),
                direction: Direction::Incoming,
            },
            LogEntry {
                date: NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
                hour: 22,
                src_ip: "10.0.0.3".to_string(),
                dst_ip: None,
                src_port: None,
                dst_port: Some(443),
                protocol: Some("TCP".to_string()),
                direction: Direction::Outgoing,
            },
        ]
    }

    #[test]
    fn test_csv_output() {
        let entries = sample_entries();
        let mut buf = Vec::new();
        write_csv(&mut buf, &entries).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(
            output.starts_with("date,hour,src_ip,dst_ip,src_port,dst_port,protocol,direction\n")
        );
        assert!(output.contains("2026-06-28,8,10.0.0.1,192.168.1.1,54321,22,TCP,in"));
        assert!(output.contains("2026-06-29,22,10.0.0.3,,,443,TCP,out"));
        assert_eq!(output.lines().count(), 3);
    }

    #[test]
    fn test_csv_empty() {
        let mut buf = Vec::new();
        write_csv(&mut buf, &[]).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(
            output,
            "date,hour,src_ip,dst_ip,src_port,dst_port,protocol,direction\n"
        );
    }
}
