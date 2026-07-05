use ufw_report::config::{AppConfig, CliArgs};

fn make_args(
    log_file: &str,
    csv: bool,
    output: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    verbose: bool,
) -> CliArgs {
    CliArgs {
        log_file: log_file.to_string(),
        csv,
        output: output.map(|s| s.to_string()),
        from: from.map(|s| s.to_string()),
        to: to.map(|s| s.to_string()),
        verbose,
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
    assert_eq!(config.log_file, "/custom/path/ufw.log");
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
    assert!(err.contains("debe ser anterior") || err.contains("--from"));
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
