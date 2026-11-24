use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{NaiveDate, NaiveDateTime};
use flate2::read::MultiGzDecoder;

use crate::error::UfwError;
use crate::models::{FileError, FileErrorKind, LogEntry, ParseStats};

use super::hash::HashingReader;
use super::parser::parse_log_line;

/// Maximum number of bytes a single `.gz` input may expand to.
pub const DEFAULT_MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// An input file resolved from the CLI, before it is read.
#[derive(Debug, Clone)]
pub struct InputFile {
    pub path: PathBuf,
    pub canonical_path: PathBuf,
    pub compressed: bool,
    pub explicit: bool,
}

/// Result of reading one input file.
pub(crate) struct ReadOutcome {
    pub entries: Vec<LogEntry>,
    pub stats: ParseStats,
    pub sha256: String,
    pub decompressed_bytes: u64,
    pub error: Option<FileError>,
}

impl ReadOutcome {
    fn failed(error: FileError) -> Self {
        Self {
            entries: Vec::new(),
            stats: ParseStats::default(),
            sha256: String::new(),
            decompressed_bytes: 0,
            error: Some(error),
        }
    }
}

/// Expands explicit paths and, optionally, their rotated siblings.
///
/// Only `<base>.<N>` and `<base>.<N>.gz` are discovered; `dateext` names are
/// intentionally out of scope for v0.3.0. Files are deduplicated by canonical
/// path and by `(device, inode)`, but never by content.
///
/// # Errors
///
/// Returns an error when an explicit path is missing, is not a regular file,
/// or cannot be opened.
pub fn resolve_inputs(paths: &[String], include_rotated: bool) -> Result<Vec<InputFile>, UfwError> {
    let mut resolved = Vec::new();
    let mut seen_paths = HashSet::new();
    let mut seen_inodes = HashSet::new();

    for raw in paths {
        let path = PathBuf::from(raw);
        let metadata = fs::metadata(&path).map_err(|error| map_open_error(raw, &error))?;
        if !metadata.is_file() {
            return Err(UfwError::NotAFile(raw.clone()));
        }
        File::open(&path).map_err(|error| map_open_error(raw, &error))?;

        push_input(
            &mut resolved,
            &path,
            true,
            &mut seen_paths,
            &mut seen_inodes,
        );

        if include_rotated && !has_gz_extension(&path) {
            for rotated in discover_rotated(&path) {
                let Ok(metadata) = fs::metadata(&rotated) else {
                    continue;
                };
                if !metadata.is_file() {
                    continue;
                }
                push_input(
                    &mut resolved,
                    &rotated,
                    false,
                    &mut seen_paths,
                    &mut seen_inodes,
                );
            }
        }
    }

    Ok(resolved)
}

fn push_input(
    resolved: &mut Vec<InputFile>,
    path: &Path,
    explicit: bool,
    seen_paths: &mut HashSet<PathBuf>,
    seen_inodes: &mut HashSet<(u64, u64)>,
) {
    let inode = inode_key(path);
    if inode.is_some_and(|key| seen_inodes.contains(&key)) {
        tracing::debug!("Skipping duplicate inode for {}", path.display());
        return;
    }

    let canonical_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !seen_paths.insert(canonical_path.clone()) {
        tracing::debug!("Skipping duplicate path for {}", path.display());
        return;
    }
    if let Some(key) = inode {
        seen_inodes.insert(key);
    }

    resolved.push(InputFile {
        path: path.to_path_buf(),
        canonical_path,
        compressed: is_gzip(path),
        explicit,
    });
}

fn inode_key(path: &Path) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path).ok()?;
        Some((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn is_gzip(path: &Path) -> bool {
    if has_gz_extension(path) {
        return true;
    }
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut magic = [0_u8; 2];
    file.read_exact(&mut magic).is_ok() && magic == [0x1f, 0x8b]
}

fn has_gz_extension(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("gz"))
}

fn discover_rotated(base: &Path) -> Vec<PathBuf> {
    let Some(parent) = base.parent() else {
        return Vec::new();
    };
    let Some(name) = base.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    let prefix = format!("{name}.");

    let Ok(entries) = fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(suffix) = file_name.strip_prefix(&prefix) else {
            continue;
        };
        let (number, compressed) = match suffix.strip_suffix(".gz") {
            Some(number) => (number, true),
            None => (suffix, false),
        };
        if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Ok(index) = number.parse::<u64>() else {
            continue;
        };
        candidates.push((index, compressed, entry.path()));
    }

    candidates.sort_by_key(|(index, compressed, _)| (*index, *compressed));
    candidates.into_iter().map(|(_, _, path)| path).collect()
}

fn map_open_error(path: &str, error: &io::Error) -> UfwError {
    match error.kind() {
        io::ErrorKind::NotFound => UfwError::LogNotFound(path.to_string()),
        io::ErrorKind::PermissionDenied => UfwError::PermissionDenied {
            path: path.to_string(),
            hint: "Run with 'sudo' or add your user to the 'adm' group".into(),
        },
        _ => UfwError::LogRead(io::Error::new(error.kind(), error.to_string())),
    }
}

/// Reads one input file, hashing the raw bytes as they are consumed.
///
/// Entries parsed before an error are kept and reported together with the
/// error, so a truncated gzip still contributes the evidence it contains.
pub(crate) fn read_input(
    file: &InputFile,
    today: NaiveDate,
    max_decompressed_bytes: u64,
) -> ReadOutcome {
    let handle = match File::open(&file.path) {
        Ok(handle) => handle,
        Err(error) => {
            let kind = if error.kind() == io::ErrorKind::PermissionDenied {
                FileErrorKind::PermissionDenied
            } else {
                FileErrorKind::Io
            };
            return ReadOutcome::failed(FileError::new(kind, error.to_string()));
        }
    };

    if file.compressed {
        read_gzip(handle, today, max_decompressed_bytes)
    } else {
        read_plain(handle, today)
    }
}

fn read_plain(file: File, today: NaiveDate) -> ReadOutcome {
    let mut hashing = HashingReader::new(file);
    let parsed = {
        let mut reader = BufReader::new(&mut hashing);
        parse_lines(&mut reader, today)
    };
    let drain_error = io::copy(&mut hashing, &mut io::sink()).err();
    let decompressed_bytes = hashing.bytes_read();
    let sha256 = hashing.finalize_hex();

    ReadOutcome {
        entries: parsed.entries,
        stats: parsed.stats,
        sha256,
        decompressed_bytes,
        error: parsed.error.or_else(|| {
            drain_error.map(|error| FileError::new(FileErrorKind::Io, error.to_string()))
        }),
    }
}

fn read_gzip(file: File, today: NaiveDate, max_decompressed_bytes: u64) -> ReadOutcome {
    let counter = Arc::new(AtomicU64::new(0));
    let limit_hit = Arc::new(AtomicBool::new(false));
    let mut hashing = HashingReader::new(file);

    let parsed = {
        let decoder = MultiGzDecoder::new(BufReader::new(&mut hashing));
        let counting = CountingReader::new(
            decoder,
            max_decompressed_bytes,
            Arc::clone(&counter),
            Arc::clone(&limit_hit),
        );
        let mut reader = BufReader::new(counting);
        parse_lines(&mut reader, today)
    };

    let drain_error = io::copy(&mut hashing, &mut io::sink()).err();
    let sha256 = hashing.finalize_hex();
    let decompressed_bytes = counter.load(Ordering::Relaxed).min(max_decompressed_bytes);

    let mut error = parsed.error;
    if limit_hit.load(Ordering::Relaxed) {
        error = Some(FileError::new(
            FileErrorKind::DecompressionLimit,
            format!("decompressed size exceeds the {max_decompressed_bytes}-byte limit"),
        ));
    } else if let Some(file_error) = error.as_mut() {
        if file_error.kind == FileErrorKind::Io {
            file_error.kind = FileErrorKind::CorruptGzip;
            file_error.message = format!("could not decompress gzip input: {}", file_error.message);
        }
    } else if let Some(drain_error) = drain_error {
        error = Some(FileError::new(FileErrorKind::Io, drain_error.to_string()));
    }

    ReadOutcome {
        entries: parsed.entries,
        stats: parsed.stats,
        sha256,
        decompressed_bytes,
        error,
    }
}

struct CountingReader<R> {
    inner: R,
    limit: u64,
    read: Arc<AtomicU64>,
    limit_hit: Arc<AtomicBool>,
}

impl<R> CountingReader<R> {
    fn new(inner: R, limit: u64, read: Arc<AtomicU64>, limit_hit: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            limit,
            read,
            limit_hit,
        }
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;
        let increment = u64::try_from(read).unwrap_or(u64::MAX);
        let total = self.read.fetch_add(increment, Ordering::Relaxed) + increment;
        if total > self.limit {
            self.limit_hit.store(true, Ordering::Relaxed);
            return Err(io::Error::other("decompressed size limit exceeded"));
        }
        Ok(read)
    }
}

struct ParseLinesOutput {
    entries: Vec<LogEntry>,
    stats: ParseStats,
    error: Option<FileError>,
}

fn parse_lines<R: BufRead>(reader: R, today: NaiveDate) -> ParseLinesOutput {
    let mut entries = Vec::new();
    let mut stats = ParseStats::default();
    let mut previous: Option<NaiveDateTime> = None;
    let mut error = None;

    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(file_error) => {
                error = Some(FileError::new(FileErrorKind::Io, file_error.to_string()));
                break;
            }
        };
        let line = line.trim();
        stats.total_lines += 1;

        if line.contains("[UFW BLOCK]") {
            stats.block_lines += 1;
            if let Some(entry) = parse_log_line(line, today) {
                if previous.is_some_and(|previous| entry.timestamp < previous) {
                    stats.out_of_order_lines += 1;
                }
                previous = Some(entry.timestamp);
                if entry.date > today {
                    stats.future_entries += 1;
                }
                entries.push(entry);
            } else {
                stats.unparsed_block_lines += 1;
            }
        } else if line.contains("[UFW ALLOW]") {
            stats.allow_lines += 1;
        } else if line.contains("[UFW AUDIT]") {
            stats.audit_lines += 1;
        } else {
            stats.other_lines += 1;
        }
    }

    ParseLinesOutput {
        entries,
        stats,
        error,
    }
}
