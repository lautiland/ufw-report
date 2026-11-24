use ufw_report::cli::{AppConfig, CliArgs};

fn make_args(
    log_file: &str,
    csv: bool,
    output: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    verbose: bool,
) -> CliArgs {
    CliArgs {
        log_file: vec![log_file.to_string()],
        csv,
        output: output.map(std::string::ToString::to_string),
        from: from.map(std::string::ToString::to_string),
        to: to.map(std::string::ToString::to_string),
        verbose,
        no_cache: false,
        config: None,
        findings: None,
        include_rotated: false,
        max_decompressed_bytes: None,
    }
}

#[test]
fn test_default_dates() {
    let args = make_args("/var/log/ufw.log", false, None, None, None, false);
    let config = AppConfig::from_cli(&args).unwrap();
    let today = chrono::Local::now().date_naive();
    assert_eq!(config.to_date, today);
    assert_eq!(config.from_date, today - chrono::TimeDelta::days(6));
}

#[test]
fn test_custom_dates() {
    let args = make_args(
        "/var/log/ufw.log",
        false,
        None,
        Some("2026-01-01"),
        Some("2026-01-31"),
        false,
    );
    let config = AppConfig::from_cli(&args).unwrap();
    assert_eq!(config.from_date.to_string(), "2026-01-01");
    assert_eq!(config.to_date.to_string(), "2026-01-31");
}

#[test]
fn test_csv_flag() {
    let args = make_args("/var/log/ufw.log", true, None, None, None, false);
    let config = AppConfig::from_cli(&args).unwrap();
    assert!(config.csv_mode);
}

#[test]
fn test_output_flag() {
    let args = make_args(
        "/var/log/ufw.log",
        false,
        Some("report.json"),
        None,
        None,
        false,
    );
    let config = AppConfig::from_cli(&args).unwrap();
    assert_eq!(config.output, Some("report.json".to_string()));
}

#[test]
fn test_log_file_custom() {
    let args = make_args("/custom/path/ufw.log", false, None, None, None, false);
    let config = AppConfig::from_cli(&args).unwrap();
    assert_eq!(config.log_files, vec!["/custom/path/ufw.log".to_string()]);
}

#[test]
fn test_repeated_log_files_are_kept() {
    let mut args = make_args("/var/log/ufw.log", false, None, None, None, false);
    args.log_file.push("/var/log/ufw.log.1".to_string());
    args.include_rotated = true;

    let config = AppConfig::from_cli(&args).unwrap();

    assert_eq!(config.log_files.len(), 2);
    assert!(config.include_rotated);
}

#[test]
fn test_decompression_limit_override_is_propagated() {
    let mut args = make_args("/var/log/ufw.log", false, None, None, None, false);
    args.max_decompressed_bytes = Some(1024);

    let config = AppConfig::from_cli(&args).unwrap();

    assert_eq!(config.max_decompressed_bytes, Some(1024));
}

#[test]
fn test_reversed_dates_returns_error() {
    let args = make_args(
        "/var/log/ufw.log",
        false,
        None,
        Some("2026-06-30"),
        Some("2026-06-28"),
        false,
    );
    let result = AppConfig::from_cli(&args);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("must be earlier") || err.contains("--from"));
}

#[test]
fn test_invalid_date_format_returns_error() {
    let args = make_args(
        "/var/log/ufw.log",
        false,
        None,
        Some("2026/01/01"),
        None,
        false,
    );
    let result = AppConfig::from_cli(&args);
    assert!(result.is_err());
}

#[test]
fn test_no_cache_flag_is_propagated() {
    let mut args = make_args("/var/log/ufw.log", false, None, None, None, false);
    args.no_cache = true;
    let config = AppConfig::from_cli(&args).unwrap();
    assert!(config.no_cache);
}

#[test]
fn test_config_and_findings_flags_are_propagated() {
    let mut args = make_args("/var/log/ufw.log", false, None, None, None, false);
    args.config = Some("analysis.toml".to_string());
    args.findings = Some("findings.md".to_string());

    let config = AppConfig::from_cli(&args).unwrap();

    assert_eq!(config.config_path.as_deref(), Some("analysis.toml"));
    assert_eq!(config.findings.as_deref(), Some("findings.md"));
}
