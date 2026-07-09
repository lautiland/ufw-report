use tracing_subscriber::EnvFilter;

pub fn init_logging(verbose: bool) {
    let filter = if verbose {
        EnvFilter::new("ufw_report=debug")
    } else {
        EnvFilter::new("ufw_report=info")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
