### **Lean Canvas for ufw-report**

**1. Problem**

* Raw UFW logs (`/var/log/syslog` or `ufw.log`) are noisy, repetitive, and difficult to interpret in real time using only `grep` or `tail`.
* Advanced monitoring systems (such as the ELK stack or Splunk) are excessively heavy, consume a lot of memory and CPU, and are impractical for small servers, VPS instances, or Raspberry Pis.
* Automated tools that actively modify firewall rules introduce security risks (they increase the attack surface) if compromised.

**2. Customer Segments**

* **Primary — Blue Teamers, Incident Responders (DFIR), and Security Auditors:** Professionals who need offline triage, precise chronological reconstruction, and evidence preservation directly on the compromised host, without relying on external connectivity.
* **Secondary — SysAdmins, DevOps, and Homelabbers:** Infrastructure administrators and self-hosting enthusiasts who benefit from the terminal UI for day-to-day visibility, but do not drive the roadmap.

**3. Unique Value Proposition (UVP)**

* *Instant forensic triage of UFW logs in your terminal:* offline heuristic analysis, precise chronological reconstruction, and reports with a verifiable chain of custody — without touching your firewall.

**4. Solution**

* Lightweight TUI with parse caching and streaming `.gz` decompression (asynchronous parsing is planned for v0.4.0+).
* Multi-file ingestion with native support for rotated and compressed logs (`.gz`), merged chronologically into a single analysis.
* Sub-hour sliding-window heuristics for scans, sweeps, and brute-force bursts, backed by second-precision timestamps.
* Offline risk scoring and findings mapped to MITRE ATT&CK where applicable, with SHA-256 hashes of the evidence read.
* **Secondary / future:** Generator of mitigation commands (`ufw deny`) for the administrator to apply manually, preserving the principle of least privilege. It is not part of the core v0.3.0 scope.

**5. Channels**

* **GitHub Releases (current):** precompiled GNU and static-musl tarballs with SHA-256 checksums.
* **Planned:** `.deb` packages, Ubuntu PPAs, and `cargo install ufw-report` via crates.io.
* Technical communities on Reddit (`r/linuxadmin`, `r/homelab`, `r/cybersecurity`).
* Forums and open-source platforms such as GitHub (gaining traction through stars and trending).

**6. Revenue Streams**

* **100% Open Source model:** The main value here could be reputation building, using the project as a technically strong centerpiece for a professional portfolio.
* **Donations:** GitHub Sponsors or BuyMeACoffee.
* **Freemium (future):** Free core features; commercial licensing for enterprise infrastructure integrations.

**7. Cost Structure**

* Practically zero initial monetary cost.
* The main cost is development time, optimizing the concurrent architecture for log processing, and repository maintenance.

**8. Key Metrics**

* Number of downloads/installations.
* Technical performance: processing time per 100,000 log lines and memory usage during intensive use.
* Forensic coverage: rotated files ingested without gaps, with coverage anomalies surfaced as integrity alerts.
* Detection precision: fewer false negatives for bursts shorter than one minute, measured against sliding-window fixtures.
* Evidence integrity: percentage of runs with complete SHA-256 hashes and execution metadata.
* Recurring users or community issues/pull requests in the repository.

**9. Unfair Advantage**

* *Forensically sound by design:* while others try to automate everything in the cloud, this tool bets on offline, local, read-only processing. It does not write to the log files, change firewall state, or modify the host configuration, and it cryptographically proves which exact files were analyzed through SHA-256. For a security-conscious profile, this is not a limitation; it is a fundamental design feature that generates immediate trust.
