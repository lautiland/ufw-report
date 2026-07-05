use std::io::Write;

use crate::models::LogEntry;

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
                crate::models::Direction::Incoming => "in",
                crate::models::Direction::Outgoing => "out",
                crate::models::Direction::Unknown => "?",
            },
        )?;
    }
    Ok(())
}

pub fn write_json<W: Write>(writer: W, entries: &[LogEntry]) -> anyhow::Result<()> {
    serde_json::to_writer(writer, entries)?;
    Ok(())
}

pub fn write_output(entries: &[LogEntry], path: &str) -> anyhow::Result<()> {
    if path == "-" {
        write_json(std::io::stdout().lock(), entries)?;
        println!();
        return Ok(());
    }

    if path.ends_with(".csv") {
        let file = std::fs::File::create(path)?;
        write_csv(file, entries)?;
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
        assert_eq!(output.lines().count(), 3); // header + 2 entries
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
    fn test_csv_empty() {
        let mut buf = Vec::new();
        write_csv(&mut buf, &[]).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(
            output,
            "date,hour,src_ip,dst_ip,src_port,dst_port,protocol,direction\n"
        );
    }

    #[test]
    fn test_json_empty() {
        let mut buf = Vec::new();
        write_json(&mut buf, &[]).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "[]");
    }
}
