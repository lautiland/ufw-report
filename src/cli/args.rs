use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "ufw-report",
    version,
    about = "UFW log analyzer & interactive TUI report"
)]
pub struct CliArgs {
    #[arg(short = 'l', long, default_value = "/var/log/ufw.log")]
    pub log_file: String,

    #[arg(long)]
    pub csv: bool,

    #[arg(short = 'o', long)]
    pub output: Option<String>,

    #[arg(long)]
    pub from: Option<String>,

    #[arg(long)]
    pub to: Option<String>,

    #[arg(short, long)]
    pub verbose: bool,
}
