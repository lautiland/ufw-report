use serde::{Deserialize, Serialize};

/// Line-level counters collected while reading the UFW log.
///
/// The counters describe the whole log file, not only the requested date
/// range, so they can be used to tell "no attacks happened" apart from
/// "the log had no usable data".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseStats {
    pub total_lines: u64,
    pub block_lines: u64,
    pub allow_lines: u64,
    pub audit_lines: u64,
    pub other_lines: u64,
    pub unparsed_block_lines: u64,
    pub out_of_order_lines: u64,
    pub future_entries: u64,
}

impl ParseStats {
    /// Number of `[UFW BLOCK]` lines that produced a usable entry.
    #[must_use]
    pub const fn parsed_block_lines(&self) -> u64 {
        self.block_lines.saturating_sub(self.unparsed_block_lines)
    }
}
