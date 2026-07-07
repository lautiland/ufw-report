use std::io::Write;

use crate::domain::{Direction, LogEntry};

/// # Errors
///
/// Returns an error if writing to the output fails.
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
