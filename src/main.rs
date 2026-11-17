use std::io::Write;

use clap::Parser;

use ufw_report::cli::{AppConfig, CliArgs};
use ufw_report::core::{self, ParseOptions};
use ufw_report::error::UfwError;
use ufw_report::logging;
use ufw_report::models::build_aggregated;
use ufw_report::output::{self, OutputFormat};
use ufw_report::threat::config::AnalysisConfig;

fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    logging::init_logging(args.verbose);

    let config = AppConfig::from_cli(&args)?;
    let output_format = OutputFormat::resolve(config.csv_mode, config.output.as_deref())?;
    let analysis_config = AnalysisConfig::load(config.config_path.as_deref())?;

    eprintln!(
        "Analyzing UFW logs ({} → {})... ",
        config.from_date, config.to_date
    );
    std::io::stderr().flush()?;

    let parse_options = ParseOptions {
        use_cache: !config.no_cache,
        ..ParseOptions::default()
    };

    let parse_result = match core::parse_ufw_log_range_with_options(
        &config.log_file,
        config.from_date,
        config.to_date,
        &parse_options,
    ) {
        Err(UfwError::PermissionDenied { path, hint }) => {
            eprintln!("\nPermission denied while reading {path}.\nHint: {hint}");
            std::process::exit(1);
        }
        Err(UfwError::LogNotFound(path)) => {
            eprintln!("\nNo log file found at {path}");
            std::process::exit(1);
        }
        result => result?,
    };

    let entry_count = parse_result.all_entries.len();
    let day_count = parse_result.reports.len();
    eprintln!("{entry_count} entries, {day_count} days");

    if let Some(format) = output_format {
        let path = config.output.as_deref().unwrap_or("-");
        output::write_output(&parse_result.all_entries, path, format)?;
        return Ok(());
    }

    if entry_count == 0 {
        eprintln!("No blocked entries found in the selected range.");
        eprintln!("(the log may be empty or you may not have read permission)");
        return Ok(());
    }

    let aggregated = build_aggregated(parse_result.reports, &parse_result.all_entries);
    let threat = ufw_report::threat::analyze(
        &parse_result.all_entries,
        config.from_date,
        config.to_date,
        parse_result.stats,
        &analysis_config,
    )?;
    ufw_report::tui::run_tui(aggregated, parse_result.all_entries, threat)?;

    Ok(())
}
