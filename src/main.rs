use std::io::Write;

use clap::Parser;

use ufw_report::cli::{AppConfig, CliArgs};
use ufw_report::core::{self, ParseOptions};
use ufw_report::error::UfwError;
use ufw_report::logging;
use ufw_report::models::build_aggregated;
use ufw_report::output::{self, FindingsFormat, OutputFormat};
use ufw_report::threat::config::AnalysisConfig;

fn report_file_errors(files: &[ufw_report::models::EvidenceFile]) {
    for file in files {
        if let Some(error) = &file.error {
            eprintln!(
                "warning: {} could only be read partially ({}): {}",
                file.path,
                file_error_label(error.kind),
                error.message
            );
        }
        if file.parse_stats.block_lines > 0 && file.parse_stats.parsed_block_lines() == 0 {
            eprintln!(
                "warning: no usable [UFW BLOCK] lines were parsed from {}",
                file.path
            );
        }
    }
}

fn file_error_label(kind: ufw_report::models::FileErrorKind) -> &'static str {
    use ufw_report::models::FileErrorKind;

    match kind {
        FileErrorKind::PermissionDenied => "permission denied",
        FileErrorKind::CorruptGzip => "corrupt gzip data",
        FileErrorKind::DecompressionLimit => "decompression limit reached",
        FileErrorKind::Io => "I/O error",
    }
}

fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    logging::init_logging(args.verbose);

    let config = AppConfig::from_cli(&args)?;
    let output_format = OutputFormat::resolve(config.csv_mode, config.output.as_deref())?;
    let analysis_config = AnalysisConfig::load(config.config_path.as_deref())?;

    if config.findings.as_deref() == Some("-") {
        let entry_export_to_stdout =
            output_format.is_some() && config.output.as_deref().unwrap_or("-") == "-";
        anyhow::ensure!(
            !entry_export_to_stdout,
            "--findings - and the entry export cannot both write to stdout"
        );
    }

    eprintln!(
        "Analyzing UFW logs ({} → {})... ",
        config.from_date, config.to_date
    );
    std::io::stderr().flush()?;

    let parse_options = ParseOptions {
        use_cache: !config.no_cache,
        include_rotated: config.include_rotated,
        max_decompressed_bytes: config
            .max_decompressed_bytes
            .unwrap_or(analysis_config.limits.max_decompressed_bytes),
        ..ParseOptions::default()
    };

    let parse_result = match core::parse_logs_with_options(
        &config.log_files,
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

    report_file_errors(&parse_result.files);

    let findings_format = config.findings.as_deref().map(FindingsFormat::resolve);
    let needs_analysis = findings_format.is_some() || output_format.is_none();
    let threat = if needs_analysis {
        Some(ufw_report::threat::analyze_with_custody(
            &parse_result.all_entries,
            config.from_date,
            config.to_date,
            parse_result.stats,
            &analysis_config,
            &parse_result.files,
            env!("CARGO_PKG_VERSION"),
        )?)
    } else {
        None
    };

    if let (Some(path), Some(format), Some(report)) =
        (config.findings.as_deref(), findings_format, threat.as_ref())
    {
        output::write_findings(report, path, format)?;
        if output_format.is_none() {
            return Ok(());
        }
    }

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
    let Some(threat) = threat else {
        anyhow::bail!("internal error: threat analysis was not computed");
    };
    ufw_report::tui::run_tui(aggregated, parse_result.all_entries, threat)?;

    Ok(())
}
