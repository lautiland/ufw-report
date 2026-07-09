use std::io::Write;

use crate::models::LogEntry;

/// # Errors
///
/// Returns an error if serialization or writing fails.
pub fn write_json<W: Write>(writer: W, entries: &[LogEntry]) -> anyhow::Result<()> {
    serde_json::to_writer(writer, entries)?;
    Ok(())
}

/// # Errors
///
/// Returns an error if file creation or writing fails.
pub fn write_output(entries: &[LogEntry], path: &str) -> anyhow::Result<()> {
    if path == "-" {
        write_json(std::io::stdout().lock(), entries)?;
        println!();
        return Ok(());
    }

    if std::path::Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("csv"))
    {
        let file = std::fs::File::create(path)?;
        super::csv::write_csv(file, entries)?;
    } else {
        let file = std::fs::File::create(path)?;
        write_json(file, entries)?;
    }

    tracing::info!("Report written to {}", path);
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
                direction: crate::models::Direction::Incoming,
            },
            LogEntry {
                date: NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
                hour: 22,
                src_ip: "10.0.0.3".to_string(),
                dst_ip: None,
                src_port: None,
                dst_port: Some(443),
                protocol: Some("TCP".to_string()),
                direction: crate::models::Direction::Outgoing,
            },
        ]
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
        assert_eq!(parsed[1]["src_ip"], "10.0.0.3");
        assert_eq!(parsed[1]["direction"], "Outgoing");
    }

    #[test]
    fn test_json_output_roundtrip() {
        let entries = sample_entries();
        let mut buf = Vec::new();
        write_json(&mut buf, &entries).unwrap();

        let deserialized: Vec<LogEntry> = serde_json::from_slice(&buf).unwrap();
        assert_eq!(deserialized.len(), 2);
        assert_eq!(deserialized[0].src_ip, entries[0].src_ip);
        assert_eq!(deserialized[1].dst_port, entries[1].dst_port);
    }

    #[test]
    fn test_json_empty() {
        let mut buf = Vec::new();
        write_json(&mut buf, &[]).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "[]");
    }
}
