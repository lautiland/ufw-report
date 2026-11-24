use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TestEnv {
    dir: tempfile::TempDir,
}

impl TestEnv {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(fixture_path(), dir.path().join("ufw.log")).unwrap();
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ufw-report"));
        command
            .arg("-l")
            .arg(self.path("ufw.log"))
            .env("XDG_CACHE_HOME", self.path("cache"))
            .env("HOME", self.path("home"));
        command
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ufw.log")
}

fn run(command: &mut Command) -> Output {
    command.output().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn june_29_args() -> [&'static str; 4] {
    ["--from", "2026-06-29", "--to", "2026-06-29"]
}

fn read_file(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn test_csv_to_stdout() {
    let env = TestEnv::new();
    let mut command = env.command();
    command.args(june_29_args()).args(["--csv", "--no-cache"]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    let csv = stdout(&output);
    assert!(
        csv.starts_with("date,hour,src_ip,dst_ip,src_port,dst_port,protocol,direction,timestamp\n")
    );
    assert!(csv.contains("2026-06-29T01:15:00"));
    assert_eq!(csv.lines().count(), 4);
    assert!(stderr(&output).contains("3 entries"));
}

#[test]
fn test_csv_with_json_output_path_fails() {
    let env = TestEnv::new();
    let mut command = env.command();
    command
        .args(june_29_args())
        .args(["--csv", "-o", env.path("report.json").to_str().unwrap()]);

    let output = run(&mut command);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("--csv"));
}

#[test]
fn test_output_json_file() {
    let env = TestEnv::new();
    let output_path = env.path("report.json");
    let mut command = env.command();
    command
        .args(june_29_args())
        .args(["--no-cache", "-o", output_path.to_str().unwrap()]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&read_file(&output_path)).unwrap();
    assert_eq!(parsed.len(), 3);
}

#[test]
fn test_output_csv_file() {
    let env = TestEnv::new();
    let output_path = env.path("report.csv");
    let mut command = env.command();
    command
        .args(june_29_args())
        .args(["--no-cache", "-o", output_path.to_str().unwrap()]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(read_file(&output_path)
        .starts_with("date,hour,src_ip,dst_ip,src_port,dst_port,protocol,direction,timestamp\n"));
}

#[test]
fn test_output_csv_extension_is_case_insensitive() {
    let env = TestEnv::new();
    let output_path = env.path("report.CSV");
    let mut command = env.command();
    command
        .args(june_29_args())
        .args(["--no-cache", "-o", output_path.to_str().unwrap()]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(read_file(&output_path).starts_with("date,hour,src_ip"));
}

#[test]
fn test_csv_flag_beats_non_json_extension() {
    let env = TestEnv::new();
    let output_path = env.path("report.txt");
    let mut command = env.command();
    command
        .args(june_29_args())
        .args(["--csv", "--no-cache", "-o", output_path.to_str().unwrap()]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(read_file(&output_path).starts_with("date,hour,src_ip"));
}

#[test]
fn test_output_dash_defaults_to_json() {
    let env = TestEnv::new();
    let mut command = env.command();
    command.args(june_29_args()).args(["--no-cache", "-o", "-"]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(parsed.len(), 3);
}

#[test]
fn test_no_cache_does_not_create_cache_files() {
    let env = TestEnv::new();
    let mut command = env.command();
    command.args(june_29_args()).args(["--csv", "--no-cache"]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!env.path("cache/ufw-report").exists());
}

#[test]
fn test_missing_log_file_exits_with_error() {
    let env = TestEnv::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_ufw-report"));
    command
        .arg("-l")
        .arg(env.path("missing.log"))
        .args(["--csv", "--no-cache"]);

    let output = run(&mut command);

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("No log file found"));
}

#[test]
fn test_reversed_dates_exit_with_error() {
    let env = TestEnv::new();
    let mut command = env.command();
    command.args(["--from", "2026-06-30", "--to", "2026-06-01", "--csv"]);

    let output = run(&mut command);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("must be earlier"));
}
