use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

struct TestEnv {
    dir: tempfile::TempDir,
}

impl TestEnv {
    fn new(fixture: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(fixture_path(fixture), dir.path().join("ufw.log")).unwrap();
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
            .args(["--from", "2026-06-28", "--to", "2026-06-30"])
            .arg("--no-cache")
            .env("XDG_CACHE_HOME", self.path("cache"))
            .env("HOME", self.path("home"));
        command
    }
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
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

fn read_file(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn findings_json(env: &TestEnv) -> serde_json::Value {
    let script = env.path("findings.json");
    let mut command = env.command();
    command.args(["--findings", script.to_str().unwrap()]);
    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    serde_json::from_str(&read_file(&script)).unwrap()
}

fn attack_findings(report: &serde_json::Value) -> Vec<&serde_json::Value> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| {
            !matches!(
                finding["kind"].as_str(),
                Some("MissingHours" | "OutOfOrderEntries" | "FutureDatedEntries" | "InputError")
            )
        })
        .collect()
}

#[test]
fn test_scan_findings_are_exported_as_json() {
    let env = TestEnv::new("threat_scan.log");
    let mut command = env.command();
    let path = env.path("findings.json");
    command.args(["--findings", path.to_str().unwrap()]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&read_file(&path)).unwrap();
    assert_eq!(report["findings"][0]["kind"], "PortScan");
    assert_eq!(report["findings"][0]["severity"], "High");
    assert_eq!(report["findings"][0]["peak"], 10);
    assert_eq!(report["profiles"][0]["ip"], "203.0.113.10");
    assert_eq!(report["profiles"][0]["risk_score"], 41);
    assert_eq!(report["coverage"]["stats"]["total_lines"], 10);
    assert_eq!(report["coverage"]["stats"]["block_lines"], 10);
}

#[test]
fn test_findings_refuse_to_overwrite_different_content() {
    let env = TestEnv::new("threat_scan.log");
    let path = env.path("findings.json");
    std::fs::write(&path, "previous evidence").unwrap();

    let mut command = env.command();
    command.args(["--findings", path.to_str().unwrap()]);
    let output = run(&mut command);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("collision"));
    assert_eq!(read_file(&path), "previous evidence");
}

#[test]
fn test_bruteforce_findings_are_exported() {
    let env = TestEnv::new("threat_bruteforce.log");
    let report = findings_json(&env);

    assert_eq!(report["findings"][0]["kind"], "BruteForce");
    assert_eq!(report["findings"][0]["peak"], 20);
}

#[test]
fn test_distributed_findings_survive_the_min_score_filter() {
    let env = TestEnv::new("threat_distributed.log");
    let report = findings_json(&env);

    assert_eq!(report["findings"][0]["kind"], "DistributedBruteForce");
    assert_eq!(
        report["findings"][0]["target_ip"].as_str(),
        Some("192.168.1.1")
    );
    assert_eq!(report["findings"][0]["target_port"], 22);
    assert_eq!(report["profiles"].as_array().unwrap().len(), 0);
}

#[test]
fn test_persistent_source_is_reported() {
    let env = TestEnv::new("threat_persistent.log");
    let report = findings_json(&env);

    assert_eq!(report["findings"][0]["kind"], "PersistentSource");
    assert_eq!(report["profiles"][0]["active_days"], 3);
}

#[test]
fn test_clean_traffic_has_no_attack_findings() {
    let env = TestEnv::new("clean.log");
    let report = findings_json(&env);

    assert!(!attack_findings(&report).iter().any(|finding| {
        matches!(
            finding["kind"].as_str(),
            Some(
                "PortScan"
                    | "HostSweep"
                    | "BruteForce"
                    | "DistributedBruteForce"
                    | "PersistentSource"
            )
        )
    }));
    assert_eq!(report["profiles"].as_array().unwrap().len(), 0);
    assert_eq!(report["coverage"]["stats"]["block_lines"], 2);
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|finding| finding["kind"] == "MissingHours"));
}

#[test]
fn test_markdown_export_uses_the_md_extension() {
    let env = TestEnv::new("threat_scan.log");
    let path = env.path("findings.md");
    let mut command = env.command();
    command.args(["--findings", path.to_str().unwrap()]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    let markdown = read_file(&path);
    assert!(markdown.starts_with("# UFW Threat Findings\n"));
    assert!(markdown.contains("Range: 2026-06-28 → 2026-06-30"));
    assert!(markdown.contains("| Port scan |"));
    assert!(markdown.contains("T1046"));
    assert!(markdown.contains("## Chain of custody"));
    assert!(markdown.contains("## Disclaimer"));
    assert!(markdown.contains("heuristic triage indicators"));
    assert!(markdown.contains("_Generated by ufw-report (offline, read-only)."));
}

#[test]
fn test_markdown_lists_network_groups() {
    let env = TestEnv::new("threat_distributed.log");
    let path = env.path("findings.md");
    let mut command = env.command();
    command.args(["--findings", path.to_str().unwrap()]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    let markdown = read_file(&path);
    assert!(markdown.contains("| Distributed brute force |"));
    assert!(markdown.contains("| `203.0.113.0/24` |"));
}

#[test]
fn test_findings_can_be_written_to_stdout() {
    let env = TestEnv::new("threat_scan.log");
    let mut command = env.command();
    command.args(["--findings", "-"]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(report["findings"][0]["kind"], "PortScan");
}

#[test]
fn test_findings_and_output_cannot_share_stdout() {
    let env = TestEnv::new("threat_scan.log");
    let mut command = env.command();
    command.args(["--findings", "-", "-o", "-"]);

    let output = run(&mut command);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("cannot both write to stdout"));
}

#[test]
fn test_findings_and_csv_cannot_share_stdout() {
    let env = TestEnv::new("threat_scan.log");
    let mut command = env.command();
    command.args(["--findings", "-", "--csv"]);

    let output = run(&mut command);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("cannot both write to stdout"));
}

#[test]
fn test_invalid_config_file_fails() {
    let env = TestEnv::new("threat_scan.log");
    let config_path = env.path("analysis.toml");
    std::fs::write(&config_path, "[subnets]\nipv4_prefix = 64\n").unwrap();
    let mut command = env.command();
    command.args([
        "--config",
        config_path.to_str().unwrap(),
        "--findings",
        env.path("findings.json").to_str().unwrap(),
    ]);

    let output = run(&mut command);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("ipv4_prefix"));
}

#[test]
fn test_findings_and_entry_export_can_be_combined() {
    let env = TestEnv::new("threat_scan.log");
    let findings_path = env.path("findings.json");
    let entries_path = env.path("entries.csv");
    let mut command = env.command();
    command.args([
        "--findings",
        findings_path.to_str().unwrap(),
        "-o",
        entries_path.to_str().unwrap(),
    ]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(read_file(&findings_path).contains("\"PortScan\""));
    assert!(read_file(&entries_path).starts_with("date,hour,src_ip"));
}

#[test]
fn test_config_file_overrides_the_scan_threshold() {
    let env = TestEnv::new("threat_scan.log");
    let config_path = env.path("analysis.toml");
    std::fs::write(&config_path, "[thresholds]\nscan_ports_per_hour = 99\n").unwrap();
    let findings_path = env.path("findings.json");
    let mut command = env.command();
    command.args([
        "--config",
        config_path.to_str().unwrap(),
        "--findings",
        findings_path.to_str().unwrap(),
    ]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&read_file(&findings_path)).unwrap();
    assert_eq!(attack_findings(&report).len(), 0);
}

#[test]
fn test_boundary_scan_keeps_exact_timestamps_and_technique() {
    let env = TestEnv::new("threat_boundary.log");
    let report = findings_json(&env);

    let scan = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["kind"] == "PortScan")
        .expect("boundary scan should be detected");

    assert_eq!(scan["first_timestamp"], "2026-06-28T10:59:30");
    assert_eq!(scan["last_timestamp"], "2026-06-28T11:01:00");
    assert_eq!(scan["first_seen"], "2026-06-28");
    assert_eq!(scan["technique"], "T1046");
    assert_eq!(scan["ports"].as_array().unwrap().len(), 10);
    assert!(scan["evidence"]
        .as_str()
        .unwrap()
        .contains("60-minute window"));
}

#[test]
fn test_narrow_window_suppresses_the_boundary_scan() {
    let env = TestEnv::new("threat_boundary.log");
    let config_path = env.path("analysis.toml");
    std::fs::write(&config_path, "[thresholds]\nscan_window_minutes = 1\n").unwrap();
    let findings_path = env.path("findings.json");
    let mut command = env.command();
    command.args([
        "--config",
        config_path.to_str().unwrap(),
        "--findings",
        findings_path.to_str().unwrap(),
    ]);

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&read_file(&findings_path)).unwrap();
    assert_eq!(attack_findings(&report).len(), 0);
}

#[test]
fn test_custody_hashes_match_the_raw_input() {
    let env = TestEnv::new("threat_boundary.log");
    let report = findings_json(&env);
    let custody = &report["custody"];

    let raw = std::fs::read(env.path("ufw.log")).unwrap();
    let expected = format!("{:x}", Sha256::digest(&raw));

    assert_eq!(custody["files"][0]["sha256"], expected);
    assert_eq!(
        custody["files"][0]["path"],
        env.path("ufw.log").to_str().unwrap()
    );
    assert_eq!(custody["tool_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(custody["config_sha256"].as_str().unwrap().len(), 64);
    assert!(custody["effective_config"]
        .as_str()
        .unwrap()
        .contains("scan_window_minutes"));
    assert!(custody["disclaimer"]
        .as_str()
        .unwrap()
        .contains("heuristic triage indicators"));
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["kind"] == "MissingHours")
        .all(|finding| finding["technique"].is_null()));
}

#[test]
fn test_unreadable_input_becomes_an_integrity_finding() {
    let dir = tempfile::tempdir().unwrap();
    let broken = dir.path().join("broken.log.gz");
    let healthy = dir.path().join("healthy.log");
    std::fs::write(&broken, b"not gzip").unwrap();
    std::fs::copy(fixture_path("threat_scan.log"), &healthy).unwrap();
    let findings_path = dir.path().join("findings.json");

    let output = Command::new(env!("CARGO_BIN_EXE_ufw-report"))
        .args([
            "-l",
            broken.to_str().unwrap(),
            "-l",
            healthy.to_str().unwrap(),
            "--from",
            "2026-06-28",
            "--to",
            "2026-06-30",
            "--no-cache",
            "--findings",
            findings_path.to_str().unwrap(),
        ])
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .env("HOME", dir.path().join("home"))
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&read_file(&findings_path)).unwrap();
    let input_error = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["kind"] == "InputError")
        .expect("unreadable input should be a finding");

    assert!(input_error["evidence"]
        .as_str()
        .unwrap()
        .contains("broken.log.gz"));
    assert_eq!(report["custody"]["files"].as_array().unwrap().len(), 2);
    assert!(report["custody"]["files"][0]["error"].is_object());
}
