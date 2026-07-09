use chrono::NaiveDate;

use super::args::CliArgs;

#[derive(Debug)]
pub struct AppConfig {
    pub log_file: String,
    pub from_date: NaiveDate,
    pub to_date: NaiveDate,
    pub csv_mode: bool,
    pub output: Option<String>,
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
            "--from ({from_date}) debe ser anterior o igual a --to ({to_date})",
        );

        Ok(AppConfig {
            log_file: args.log_file.clone(),
            from_date,
            to_date,
            csv_mode: args.csv,
            output: args.output.clone(),
        })
    }
}
