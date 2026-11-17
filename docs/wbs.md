### **WBS: ufw-report (Development and Expansion)**

#### **1.0 Core Engine & Data Processing**

*Analysis is currently synchronous. The goal is to preserve the current accuracy and prepare the engine for very large volumes of data.*

* **1.1 Log Parser (Current State)**
* 1.1.1 UFW log parsing for IPv4 and IPv6.
* 1.1.2 Protocol normalization (numeric to name).
* 1.1.3 Traffic direction detection (IN/OUT).
* 1.1.4 Optional JSON cache, invalidation by log fingerprint and format version.

* **1.2 Scalability and Performance (Future)**
* 1.2.1 Refactor to a multithreaded architecture for concurrent processing of large log files, avoiding UI stalls.
* 1.2.2 Extended parser for TCP flags, window size, and TTL (needed for offline fingerprinting).

---

#### **2.0 Threat Heuristics Engine (New)**

*The core value proposition that turns data into actionable offline intelligence.*

* **2.1 Pattern Detection**
* 2.1.1 Brute-force detection module (bursts against administrative ports).
* 2.1.2 Port-scanning detection module (horizontal and vertical scans).
* 2.1.3 Anomalous-volume detection module (possible DoS attacks).

* **2.2 Risk Score System**
* 2.2.1 Local weighting algorithm based on traffic severity.

* **2.3 Static Fingerprinting**
* 2.3.1 Local database (JSON/YAML) embedded in the binary with signatures of common scanning tools (Nmap, Masscan).

---

#### **3.0 Terminal User Interface (TUI)**

*Expanding the current views to accommodate the new intelligence without sacrificing performance.*

* **3.1 Views and Controls (Current State)**
* 3.1.1 Tab system: Overview, Daily, Hourly, and Raw.
* 3.1.2 Keyboard navigation and scrolling interactions.

* **3.2 Security Dashboard (Future)**
* 3.2.1 New "Threats/Alerts" tab that ranks IPs by the Risk Score instead of volume alone.
* 3.2.2 Visual identifiers (tags or terminal colors) for the detected threat type directly in the "Overview" and "Raw" views.

* **3.3 Interactive Forensic Analysis (Future)**
* 3.3.1 TUI controls to isolate and zoom into specific time windows (for example, selecting an anomalous spike in the Daily chart and expanding the details of that incident).

---

#### **4.0 CLI & Active-Passive Mitigation**

*Providing blocking solutions without the tool executing privileged commands.*

* **4.1 Arguments and Export (Current State)**
* 4.1.1 Date handling (`--from`, `--to`) and log paths.
* 4.1.2 Export of enriched data to CSV and JSON, including pipeline support (`-o -`).

* **4.2 Mitigation Generation (Future)**
* 4.2.1 New flag or TUI shortcut to generate blocking scripts (`bash` with `ufw deny` commands) for the user to run manually and under control.

---

#### **5.0 Architecture, Quality, and Distribution**

*Ensuring stability and making adoption easier for sysadmins.*

* **5.1 Base Quality and Security (Current State)**
* 5.1.1 Test suite covering parser, cache, configuration, models, output, CLI, and TUI navigation.
* 5.1.2 CI pipeline with GitHub Actions (fmt, clippy, tests, build) on every branch.
* 5.1.3 Panic hook that restores the terminal when an error occurs.

* **5.2 Distribution (Future)**
* 5.2.1 Packaging for community managers (Cargo) and static binaries for air-gapped deployments.
* 5.2.2 Creation of `.deb` packages or PPAs for Ubuntu/Debian environments.
