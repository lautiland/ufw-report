use clap::Parser;

#[derive(Parser, Debug)]
// CLI flags are naturally boolean; grouping them into enums would not help clap.
#[allow(clippy::struct_excessive_bools)]
#[command(
    name = "ufw-report",
    version,
    about = "Analyze UFW logs and explore blocked traffic in an interactive TUI",
    long_about = "Reads a UFW log, aggregates blocked traffic by day, hour, source IP, port and \
                  protocol, and displays it in an interactive terminal dashboard. It can also \
                  export the parsed entries as CSV or JSON.\n\nBy default it analyzes the last \
                  7 days and enters the TUI. Use --csv or -o to export and exit."
)]
pub struct CliArgs {
    #[arg(
        short = 'l',
        long,
        value_name = "PATH",
        default_value = "/var/log/ufw.log",
        action = clap::ArgAction::Append,
        help = "Path to a UFW log file; repeat the flag to analyze several files"
    )]
    pub log_file: Vec<String>,

    #[arg(
        long,
        help = "Also read rotated siblings named <log>.<N> and <log>.<N>.gz"
    )]
    pub include_rotated: bool,

    #[arg(
        long,
        value_name = "BYTES",
        help = "Maximum decompressed size per .gz input (default: 4294967296, i.e. 4 GiB)"
    )]
    pub max_decompressed_bytes: Option<u64>,

    #[arg(long, help = "Export the parsed entries as CSV and exit")]
    pub csv: bool,

    #[arg(
        short = 'o',
        long,
        value_name = "PATH",
        help = "Write output to PATH; use '-' for stdout. With --csv the output is always CSV"
    )]
    pub output: Option<String>,

    #[arg(
        long,
        value_name = "DATE",
        help = "Start date (YYYY-MM-DD). Defaults to 6 days ago"
    )]
    pub from: Option<String>,

    #[arg(
        long,
        value_name = "DATE",
        help = "End date (YYYY-MM-DD). Defaults to today"
    )]
    pub to: Option<String>,

    #[arg(short = 'v', long, help = "Enable verbose logging")]
    pub verbose: bool,

    #[arg(long, help = "Do not read or write the parse cache")]
    pub no_cache: bool,

    #[arg(
        long,
        value_name = "PATH",
        help = "Load analysis thresholds from an explicit TOML config file"
    )]
    pub config: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Write threat findings to PATH as JSON, or Markdown when the path ends in .md; use '-' for stdout"
    )]
    pub findings: Option<String>,
}
