use std::io::Write;

use crate::models::LogEntry;

use super::OutputFormat;

/// # Errors
///
/// Returns an error if serialization or writing fails.
pub fn write_json<W: Write>(writer: W, entries: &[LogEntry]) -> anyhow::Result<()> {
    serde_json::to_writer(writer, entries)?;
    Ok(())
}

/// Writes entries to `path` in the requested format.
///
/// Use `-` to write to stdout.
///
/// # Errors
///
/// Returns an error if file creation or writing fails.
pub fn write_output(entries: &[LogEntry], path: &str, format: OutputFormat) -> anyhow::Result<()> {
    if path == "-" {
        match format {
            OutputFormat::Csv => super::csv::write_csv(std::io::stdout().lock(), entries)?,
            OutputFormat::Json => {
                write_json(std::io::stdout().lock(), entries)?;
                println!();
            }
        }
        return Ok(());
    }

    super::safe::write_output_file(path, |file| match format {
        OutputFormat::Csv => super::csv::write_csv(&mut *file, entries),
        OutputFormat::Json => write_json(&mut *file, entries),
    })?;

    tracing::info!("Report written to {}", path);
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
        first.direction = crate::models::Direction::Incoming;

        let mut second = LogEntry::new(
            NaiveDate::from_ymd_opt(2026, 6, 29)
                .unwrap()
                .and_hms_opt(22, 5, 6)
                .unwrap(),
            "10.0.0.3".to_string(),
        );
        second.dst_port = Some(443);
        second.protocol = Some("TCP".to_string());
        second.direction = crate::models::Direction::Outgoing;

        vec![first, second]
    }

    #[test]
    fn test_json_output() {
        let entries = sample_entries();
        let mut buf = Vec::new();
        write_json(&mut buf, &entries).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["src_ip"], "10.0.0.1");
        assert_eq!(parsed[0]["dst_port"], 22);
        assert_eq!(parsed[0]["timestamp"], "2026-06-28T08:12:34");
        assert_eq!(parsed[1]["src_ip"], "10.0.0.3");
        assert_eq!(parsed[1]["direction"], "Outgoing");
        assert_eq!(parsed[1]["timestamp"], "2026-06-29T22:05:06");
    }

    #[test]
    fn test_json_output_roundtrip() {
        let entries = sample_entries();
        let mut buf = Vec::new();
        write_json(&mut buf, &entries).unwrap();

        let deserialized: Vec<LogEntry> = serde_json::from_slice(&buf).unwrap();
        assert_eq!(deserialized.len(), 2);
        assert_eq!(deserialized[0].src_ip, entries[0].src_ip);
        assert_eq!(deserialized[0].timestamp, entries[0].timestamp);
        assert_eq!(deserialized[1].dst_port, entries[1].dst_port);
        assert_eq!(deserialized[1].timestamp, entries[1].timestamp);
    }

    #[test]
    fn test_json_empty() {
        let mut buf = Vec::new();
        write_json(&mut buf, &[]).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "[]");
    }
}
