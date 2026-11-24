use std::io::Write;

use crate::models::{Direction, LogEntry};

/// # Errors
///
/// Returns an error if writing to the writer fails.
pub fn write_csv<W: Write>(mut writer: W, entries: &[LogEntry]) -> anyhow::Result<()> {
    writeln!(
        writer,
        "date,hour,src_ip,dst_ip,src_port,dst_port,protocol,direction,timestamp"
    )?;
    for e in entries {
        writeln!(
            writer,
            "{},{},{},{},{},{},{},{},{}",
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
            e.timestamp.format("%Y-%m-%dT%H:%M:%S"),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn sample_entries() -> Vec<LogEntry> {
        let mut first = LogEntry::new(
            NaiveDate::from_ymd_opt(2026, 6, 28)
                .unwrap()
                .and_hms_opt(8, 12, 34)
                .unwrap(),
            "10.0.0.1".to_string(),
        );
        first.dst_ip = Some("192.168.1.1".to_string());
        first.src_port = Some(54321);
        first.dst_port = Some(22);
        first.protocol = Some("TCP".to_string());
        first.direction = Direction::Incoming;

        let mut second = LogEntry::new(
            NaiveDate::from_ymd_opt(2026, 6, 29)
                .unwrap()
                .and_hms_opt(22, 5, 6)
                .unwrap(),
            "10.0.0.3".to_string(),
        );
        second.dst_port = Some(443);
        second.protocol = Some("TCP".to_string());
        second.direction = Direction::Outgoing;

        vec![first, second]
    }

    #[test]
    fn test_csv_output() {
        let entries = sample_entries();
        let mut buf = Vec::new();
        write_csv(&mut buf, &entries).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.starts_with(
            "date,hour,src_ip,dst_ip,src_port,dst_port,protocol,direction,timestamp\n"
        ));
        assert!(output
            .contains("2026-06-28,8,10.0.0.1,192.168.1.1,54321,22,TCP,in,2026-06-28T08:12:34"));
        assert!(output.contains("2026-06-29,22,10.0.0.3,,,443,TCP,out,2026-06-29T22:05:06"));
        assert_eq!(output.lines().count(), 3);
    }

    #[test]
    fn test_csv_empty() {
        let mut buf = Vec::new();
        write_csv(&mut buf, &[]).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(
            output,
            "date,hour,src_ip,dst_ip,src_port,dst_port,protocol,direction,timestamp\n"
        );
    }
}
