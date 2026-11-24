use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use ufw_report::core::{parse_logs_with_options, ParseOptions};
use ufw_report::models::FileErrorKind;

const FROM: &str = "2026-06-01";
const TO: &str = "2026-06-30";

fn block_line(timestamp: &str, src: &str, port: u16) -> String {
    format!(
        "{timestamp} host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb SRC={src} DST=192.0.2.1 \
         LEN=60 PROTO=TCP SPT=40000 DPT={port} WINDOW=65535\n"
    )
}

fn write_plain(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
}

fn write_gzip(path: &Path, contents: &str) {
    let file = std::fs::File::create(path).unwrap();
    let mut encoder = GzEncoder::new(file, Compression::default());
    encoder.write_all(contents.as_bytes()).unwrap();
    encoder.finish().unwrap();
}

fn gzip_bytes(contents: &str) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(contents.as_bytes()).unwrap();
    encoder.finish().unwrap()
}

fn options(cache_dir: &Path, include_rotated: bool) -> ParseOptions {
    ParseOptions {
        use_cache: false,
        cache_dir: Some(cache_dir.to_path_buf()),
        reference_date: Some(NaiveDate::from_ymd_opt(2026, 6, 30).unwrap()),
        include_rotated,
        ..ParseOptions::default()
    }
}

fn parse(
    paths: &[PathBuf],
    cache_dir: &Path,
    include_rotated: bool,
) -> ufw_report::core::ParseResult {
    let paths: Vec<String> = paths
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    parse_logs_with_options(
        &paths,
        NaiveDate::parse_from_str(FROM, "%Y-%m-%d").unwrap(),
        NaiveDate::parse_from_str(TO, "%Y-%m-%d").unwrap(),
        &options(cache_dir, include_rotated),
    )
    .unwrap()
}

#[test]
fn test_multiple_files_are_merged_and_sorted() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.log");
    let second = dir.path().join("second.log");
    write_plain(&first, &block_line("2026-06-28T10:00:00", "10.0.0.2", 22));
    write_plain(&second, &block_line("2026-06-28T09:00:00", "10.0.0.1", 80));

    let result = parse(&[first, second], dir.path(), false);

    assert_eq!(result.files.len(), 2);
    assert_eq!(result.all_entries.len(), 2);
    assert_eq!(result.all_entries[0].src_ip, "10.0.0.1");
    assert_eq!(result.all_entries[1].src_ip, "10.0.0.2");
    assert_eq!(result.stats.total_lines, 2);
}

#[test]
fn test_duplicate_paths_are_read_once() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("ufw.log");
    write_plain(&log, &block_line("2026-06-28T10:00:00", "10.0.0.2", 22));

    let result = parse(&[log.clone(), log], dir.path(), false);

    assert_eq!(result.files.len(), 1);
    assert_eq!(result.all_entries.len(), 1);
}

#[test]
fn test_include_rotated_reads_numbered_and_gzip_files() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("ufw.log");
    write_plain(&log, &block_line("2026-06-28T10:00:00", "10.0.0.1", 22));
    write_plain(
        &dir.path().join("ufw.log.1"),
        &block_line("2026-06-27T10:00:00", "10.0.0.2", 80),
    );
    write_gzip(
        &dir.path().join("ufw.log.2.gz"),
        &block_line("2026-06-26T10:00:00", "10.0.0.3", 443),
    );

    let without_rotated = parse(std::slice::from_ref(&log), dir.path(), false);
    assert_eq!(without_rotated.files.len(), 1);
    assert_eq!(without_rotated.all_entries.len(), 1);

    let rotated = parse(&[log], dir.path(), true);
    assert_eq!(rotated.files.len(), 3);
    assert_eq!(rotated.all_entries.len(), 3);
    assert_eq!(rotated.all_entries[0].src_ip, "10.0.0.3");
    assert_eq!(rotated.all_entries[2].src_ip, "10.0.0.1");
    assert!(rotated.files.iter().any(|file| file.compressed));
}

#[test]
fn test_rotated_discovery_ignores_unrelated_names() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("ufw.log");
    write_plain(&log, &block_line("2026-06-28T10:00:00", "10.0.0.1", 22));
    write_plain(
        &dir.path().join("ufw.log-20260627"),
        &block_line("2026-06-27T10:00:00", "10.0.0.2", 80),
    );
    write_plain(
        &dir.path().join("ufw.log.old"),
        &block_line("2026-06-26T10:00:00", "10.0.0.3", 443),
    );

    let result = parse(&[log], dir.path(), true);

    assert_eq!(result.files.len(), 1);
}

#[test]
fn test_identical_packets_in_the_same_second_are_both_kept() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("ufw.log");
    let line = block_line("2026-06-28T10:00:00", "10.0.0.1", 22);
    write_plain(&log, &(line.clone() + &line));

    let result = parse(&[log], dir.path(), false);

    assert_eq!(result.all_entries.len(), 2);
    assert_eq!(result.files[0].parse_stats.block_lines, 2);
}

#[test]
fn test_invalid_gzip_is_reported_without_aborting_other_files() {
    let dir = tempfile::tempdir().unwrap();
    let broken = dir.path().join("broken.log.gz");
    std::fs::write(&broken, b"this is not gzip data").unwrap();
    let healthy = dir.path().join("healthy.log");
    write_plain(&healthy, &block_line("2026-06-28T10:00:00", "10.0.0.1", 22));

    let result = parse(&[broken, healthy], dir.path(), false);

    assert_eq!(result.all_entries.len(), 1);
    assert_eq!(result.files.len(), 2);
    let failed = result
        .files
        .iter()
        .find(|file| file.path.ends_with("broken.log.gz"))
        .unwrap();
    let error = failed.error.as_ref().unwrap();
    assert_eq!(error.kind, FileErrorKind::CorruptGzip);
}

#[test]
fn test_truncated_gzip_keeps_entries_read_so_far() {
    let dir = tempfile::tempdir().unwrap();
    let compressed = dir.path().join("truncated.log.gz");
    let contents = block_line("2026-06-28T09:00:00", "10.0.0.1", 22)
        + &block_line("2026-06-28T10:00:00", "10.0.0.2", 80);
    let mut bytes = gzip_bytes(&contents);
    bytes.truncate(bytes.len() - 8);
    std::fs::write(&compressed, bytes).unwrap();

    let result = parse(&[compressed], dir.path(), false);

    assert_eq!(result.all_entries.len(), 2);
    let error = result.files[0].error.as_ref().unwrap();
    assert_eq!(error.kind, FileErrorKind::CorruptGzip);
}

#[test]
fn test_decompression_limit_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let compressed = dir.path().join("large.log.gz");
    let mut contents = String::new();
    for index in 0..500 {
        contents.push_str(&block_line(
            &format!("2026-06-28T10:00:{:02}", index % 60),
            &format!("10.0.0.{}", index % 250 + 1),
            u16::try_from(1024 + index).unwrap(),
        ));
    }
    write_gzip(&compressed, &contents);

    let paths = vec![compressed.to_string_lossy().into_owned()];
    let result = parse_logs_with_options(
        &paths,
        NaiveDate::parse_from_str(FROM, "%Y-%m-%d").unwrap(),
        NaiveDate::parse_from_str(TO, "%Y-%m-%d").unwrap(),
        &ParseOptions {
            max_decompressed_bytes: 512,
            ..options(dir.path(), false)
        },
    )
    .unwrap();

    let error = result.files[0].error.as_ref().unwrap();
    assert_eq!(error.kind, FileErrorKind::DecompressionLimit);
}

#[test]
fn test_sha256_covers_raw_file_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("ufw.log.gz");
    write_gzip(&log, &block_line("2026-06-28T10:00:00", "10.0.0.1", 22));

    let result = parse(std::slice::from_ref(&log), dir.path(), false);

    let raw = std::fs::read(&log).unwrap();
    let expected = format!("{:x}", Sha256::digest(&raw));
    assert_eq!(result.files[0].sha256, expected);
    assert!(result.files[0].decompressed_bytes > 0);
}

#[test]
fn test_cache_is_validated_per_file() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.log");
    let second = dir.path().join("second.log");
    write_plain(&first, &block_line("2026-06-28T09:00:00", "10.0.0.1", 22));
    write_plain(&second, &block_line("2026-06-28T10:00:00", "10.0.0.2", 80));

    let mut cache_options = options(cache_dir.path(), false);
    cache_options.use_cache = true;
    let paths = vec![
        first.to_string_lossy().into_owned(),
        second.to_string_lossy().into_owned(),
    ];
    let from = NaiveDate::parse_from_str(FROM, "%Y-%m-%d").unwrap();
    let to = NaiveDate::parse_from_str(TO, "%Y-%m-%d").unwrap();

    let first_run = parse_logs_with_options(&paths, from, to, &cache_options).unwrap();
    assert!(first_run.files.iter().all(|file| !file.from_cache));

    let second_run = parse_logs_with_options(&paths, from, to, &cache_options).unwrap();
    assert!(second_run.files.iter().all(|file| file.from_cache));
    assert_eq!(second_run.all_entries.len(), 2);

    write_plain(&second, &block_line("2026-06-28T10:00:01", "10.0.0.3", 443));
    let third_run = parse_logs_with_options(&paths, from, to, &cache_options).unwrap();
    assert!(third_run.files[0].from_cache);
    assert!(!third_run.files[1].from_cache);
    assert_eq!(third_run.files[1].sha256.len(), 64);
}

fn run_cli(args: &[&std::ffi::OsStr]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_ufw-report"))
        .args(args)
        .env(
            "XDG_CACHE_HOME",
            std::env::temp_dir().join("ufw-report-test-cache"),
        )
        .output()
        .unwrap()
}

#[test]
fn test_cli_reads_repeated_log_files_and_rotated_siblings() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("ufw.log");
    let other = dir.path().join("other.log");
    write_plain(&base, &block_line("2026-06-28T09:00:00", "10.0.0.1", 22));
    write_plain(&other, &block_line("2026-06-28T10:00:00", "10.0.0.2", 80));
    write_gzip(
        &dir.path().join("ufw.log.1.gz"),
        &block_line("2026-06-27T10:00:00", "10.0.0.3", 443),
    );

    let output = run_cli(&[
        "-l".as_ref(),
        base.as_os_str(),
        "-l".as_ref(),
        other.as_os_str(),
        "--include-rotated".as_ref(),
        "--csv".as_ref(),
        "--no-cache".as_ref(),
        "--from".as_ref(),
        "2026-06-01".as_ref(),
        "--to".as_ref(),
        "2026-06-30".as_ref(),
    ]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let csv = String::from_utf8_lossy(&output.stdout);
    assert_eq!(csv.lines().count(), 4);
    assert!(csv.contains("10.0.0.3"));
}

#[test]
fn test_cli_reports_partial_read_and_keeps_going() {
    let dir = tempfile::tempdir().unwrap();
    let broken = dir.path().join("broken.log.gz");
    let healthy = dir.path().join("healthy.log");
    std::fs::write(&broken, b"not gzip").unwrap();
    write_plain(&healthy, &block_line("2026-06-28T10:00:00", "10.0.0.2", 80));

    let output = run_cli(&[
        "-l".as_ref(),
        broken.as_os_str(),
        "-l".as_ref(),
        healthy.as_os_str(),
        "--csv".as_ref(),
        "--no-cache".as_ref(),
        "--from".as_ref(),
        "2026-06-01".as_ref(),
        "--to".as_ref(),
        "2026-06-30".as_ref(),
    ]);

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("could only be read partially"));
    let csv = String::from_utf8_lossy(&output.stdout);
    assert_eq!(csv.lines().count(), 2);
}
