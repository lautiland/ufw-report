use chrono::NaiveDate;

use super::args::CliArgs;

#[derive(Debug)]
pub struct AppConfig {
    pub log_files: Vec<String>,
    pub from_date: NaiveDate,
    pub to_date: NaiveDate,
    pub csv_mode: bool,
    pub output: Option<String>,
    pub no_cache: bool,
    pub config_path: Option<String>,
    pub findings: Option<String>,
    pub include_rotated: bool,
    pub max_decompressed_bytes: Option<u64>,
}

impl AppConfig {
    /// # Errors
    ///
    /// Returns an error if the date parsing fails or `--from` is after `--to`.
    pub fn from_cli(args: &CliArgs) -> anyhow::Result<Self> {
        let today = chrono::Local::now().date_naive();

        let from_date = match &args.from {
            Some(s) => NaiveDate::parse_from_str(s, "%Y-%m-%d")?,
            None => today - chrono::Duration::days(6),
        };

        let to_date = match &args.to {
            Some(s) => NaiveDate::parse_from_str(s, "%Y-%m-%d")?,
            None => today,
        };

        anyhow::ensure!(
            from_date <= to_date,
            "--from ({from_date}) must be earlier than or equal to --to ({to_date})",
        );

        anyhow::ensure!(
            !args.log_file.is_empty(),
            "at least one --log-file path is required"
        );

        Ok(AppConfig {
            log_files: args.log_file.clone(),
            from_date,
            to_date,
            csv_mode: args.csv,
            output: args.output.clone(),
            no_cache: args.no_cache,
            config_path: args.config.clone(),
            findings: args.findings.clone(),
            include_rotated: args.include_rotated,
            max_decompressed_bytes: args.max_decompressed_bytes,
        })
    }
}
