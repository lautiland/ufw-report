use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::ParseStats;

/// Why an input file could not be read completely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileErrorKind {
    PermissionDenied,
    CorruptGzip,
    DecompressionLimit,
    Io,
}

/// A read error tied to one input file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileError {
    pub kind: FileErrorKind,
    pub message: String,
}

impl FileError {
    #[must_use]
    pub fn new(kind: FileErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// Per-file evidence collected while producing a report.
///
/// `sha256` always covers the raw bytes stored on disk: for a `.gz` file that
/// means the compressed bytes, not the decompressed stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFile {
    pub path: String,
    pub canonical_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub decompressed_bytes: u64,
    pub modified_at: Option<DateTime<Utc>>,
    pub compressed: bool,
    pub from_cache: bool,
    pub parse_stats: ParseStats,
    pub error: Option<FileError>,
}
