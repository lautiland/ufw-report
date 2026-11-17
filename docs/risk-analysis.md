### **Risk Register for `ufw-report`**

### **Risk 1: Parser breakage due to log format changes**
* **Category:** Technical
* **Description:** Parser breakage caused by changes in the UFW log format.
* **Causes:** Major Linux kernel, netfilter, or UFW updates that change the syslog syntax.
* **Consequences:** The TUI shows empty or incorrect data, or the application panics because a regex no longer matches.
* **Probability:** Low
* **Impact:** Critical
* **Trigger:** GitHub issue reports from users on Ubuntu >= 26.04.
* **Response Plan (Mitigation):** Maintain a robust test suite with log samples from multiple distribution versions.
* **Contingency Plan:** Release a hotfix that degrades gracefully: warn the user about an unknown format instead of crashing.
* **Notes:** The risk increases if non-Debian distributions are added.

### **Risk 2: TUI freeze**
* **Category:** Performance
* **Description:** TUI freeze while processing massive files.
* **Causes:** The `ufw.log` file is excessively large (for example, > 5 GB) due to a sustained DoS attack.
* **Consequences:** The main thread blocks, the interface stops responding to commands (`Ctrl+C`), and the user must kill the process.
* **Probability:** Medium
* **Impact:** High
* **Trigger:** TUI response time above 2 seconds when switching tabs.
* **Response Plan (Mitigation):** Implement asynchronous or multithreaded processing, separating the parsing engine from TUI rendering.
* **Contingency Plan:** Limit reading to the last 500 MB by default and require an explicit flag for a full read.
* **Notes:** Essential given the profile of demanding sysadmins.

### **Risk 3: False positives in the heuristics engine**
* **Category:** Security / Functional
* **Description:** False positives in threat detection.
* **Causes:** Poorly calibrated Risk Score parameters; normal internal network traffic is labeled as a "Critical Attack".
* **Consequences:** Loss of user trust in the tool; alert fatigue defeats the purpose of the dashboard.
* **Probability:** High
* **Impact:** Medium
* **Trigger:** More than 3 community reports of incorrect detections in local traffic.
* **Response Plan (Mitigation):** Provide `.toml` configuration files so users can calibrate heuristic weights for their environment.
* **Contingency Plan:** Temporarily disable critical labels by default until the algorithm is adjusted locally.
* **Notes:** Static fingerprinting is prone to errors in complex networks.

### **Risk 4: Runtime failures due to library incompatibility (`glibc`)**
* **Category:** Distribution
* **Description:** Runtime failures caused by missing operating system dependencies.
* **Causes:** Standard dynamically linked Rust builds running on corporate servers with very old Linux versions (for example, CentOS 7).
* **Consequences:** The error `version 'GLIBC_2.XX' not found` blocks adoption.
* **Probability:** Medium
* **Impact:** High
* **Trigger:** Failure reports for binaries downloaded from GitHub Releases.
* **Response Plan (Mitigation):** Configure CI (GitHub Actions) to build static versions using `x86_64-unknown-linux-musl`.
* **Contingency Plan:** Clearly document how users can build from source with `cargo build`.
* **Notes:** Critical for air-gapped deployments that cannot be updated easily.
