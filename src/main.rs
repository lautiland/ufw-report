use std::io::Write;

use clap::Parser;

use ufw_report::cli::{AppConfig, CliArgs};
use ufw_report::core;
use ufw_report::error::UfwError;
use ufw_report::logging;
use ufw_report::models::build_aggregated;
use ufw_report::output;

fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    logging::init_logging(args.verbose);

    let config = AppConfig::from_cli(&args)?;

    eprintln!(
        "🔍 Analyzing UFW logs ({} → {})... ",
        config.from_date, config.to_date
    );
    std::io::stderr().flush()?;

    let parse_result =
        match core::parse_ufw_log_range(&config.log_file, config.from_date, config.to_date) {
            Err(UfwError::PermissionDenied { path, hint }) => {
                eprintln!("\nPermiso denegado al leer {path}.\nSugerencia: {hint}");
                std::process::exit(1);
            }
            Err(UfwError::LogNotFound(path)) => {
                eprintln!("\nNo se encontró el archivo de log: {path}");
                std::process::exit(1);
            }
            result => result?,
        };

    let entry_count = parse_result.all_entries.len();
    let day_count = parse_result.reports.len();
    eprintln!("{entry_count} entries, {day_count} days");

    if let Some(ref output_path) = config.output {
        output::write_output(&parse_result.all_entries, output_path)?;
        return Ok(());
    }

    if config.csv_mode {
        output::write_csv(std::io::stdout().lock(), &parse_result.all_entries)?;
        return Ok(());
    }

    if entry_count == 0 {
        eprintln!("⚠️  No se encontraron entradas bloqueadas en el rango especificado.");
        eprintln!("   (puede que no tengas permisos o el archivo esté vacío)");
        return Ok(());
    }

    let aggregated = build_aggregated(parse_result.reports, &parse_result.all_entries);
    ufw_report::tui::run_tui(aggregated, parse_result.all_entries)?;

    Ok(())
}
