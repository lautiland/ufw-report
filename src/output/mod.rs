use std::path::Path;

pub mod csv;
pub mod findings;
pub mod json;

pub use csv::write_csv;
pub use findings::{render_markdown, write_findings, FindingsFormat};
pub use json::{write_json, write_output};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Csv,
    Json,
}

impl OutputFormat {
    /// Resolves the output format from the CLI flags.
    ///
    /// `--csv` always wins. If it is combined with an explicit `.json` output
    /// path, the contradiction is reported instead of silently ignoring the
    /// flag.
    ///
    /// # Errors
    ///
    /// Returns an error when `--csv` is combined with a `.json` output path.
    pub fn resolve(csv: bool, output: Option<&str>) -> anyhow::Result<Option<Self>> {
        match (csv, output) {
            (true, Some(path)) if path != "-" && has_extension(path, "json") => {
                anyhow::bail!(
                    "--csv was requested but the output path '{path}' ends in .json; \
                     use a .csv path or drop --csv"
                )
            }
            (true, _) => Ok(Some(Self::Csv)),
            (false, Some(path)) if has_extension(path, "csv") => Ok(Some(Self::Csv)),
            (false, Some(_)) => Ok(Some(Self::Json)),
            (false, None) => Ok(None),
        }
    }
}

fn has_extension(path: &str, extension: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(extension))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_flag_always_wins() {
        assert_eq!(
            OutputFormat::resolve(true, None).unwrap(),
            Some(OutputFormat::Csv)
        );
        assert_eq!(
            OutputFormat::resolve(true, Some("-")).unwrap(),
            Some(OutputFormat::Csv)
        );
        assert_eq!(
            OutputFormat::resolve(true, Some("report.txt")).unwrap(),
            Some(OutputFormat::Csv)
        );
        assert_eq!(
            OutputFormat::resolve(true, Some("report.csv")).unwrap(),
            Some(OutputFormat::Csv)
        );
    }

    #[test]
    fn test_csv_flag_rejects_json_output() {
        let error = OutputFormat::resolve(true, Some("report.json")).unwrap_err();
        assert!(error.to_string().contains("--csv"));
    }

    #[test]
    fn test_output_extension_infers_format() {
        assert_eq!(
            OutputFormat::resolve(false, Some("report.CSV")).unwrap(),
            Some(OutputFormat::Csv)
        );
        assert_eq!(
            OutputFormat::resolve(false, Some("report.json")).unwrap(),
            Some(OutputFormat::Json)
        );
        assert_eq!(
            OutputFormat::resolve(false, Some("report")).unwrap(),
            Some(OutputFormat::Json)
        );
    }

    #[test]
    fn test_no_export_flags_means_tui() {
        assert_eq!(OutputFormat::resolve(false, None).unwrap(), None);
    }
}
