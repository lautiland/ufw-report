# Quickstart: Forensic Triage Validation

Prerequisites: Rust 1.82+, a Linux shell, and the repository checked out.

```bash
cargo build --release --locked
cargo test --all-targets --locked
```

## 1. Rotation set

```bash
tmp=$(mktemp -d)
printf '2026-06-28T10:00:00 host kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.10 DST=192.0.2.1 PROTO=TCP SPT=40000 DPT=1\n' > "$tmp/ufw.log"
printf '2026-06-27T10:00:00 host kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.11 DST=192.0.2.1 PROTO=TCP SPT=40000 DPT=2\n' > "$tmp/ufw.log.1"
gzip -c "$tmp/ufw.log.1" > "$tmp/ufw.log.2.gz"

./target/release/ufw-report -l "$tmp/ufw.log" --include-rotated \
  --from 2026-06-25 --to 2026-06-30 --findings "$tmp/findings.json"
```

Expected: `custody.files` has three entries; each `sha256` matches
`sha256sum` on the raw file (the `.gz` hash covers the compressed bytes).

## 2. Burst across an hour boundary

Create a fixture with ten distinct destination ports between `10:59:30` and
`11:01:10`, then:

```bash
./target/release/ufw-report -l "$tmp/burst.log" --from 2026-06-28 --to 2026-06-28 \
  --findings "$tmp/burst.json" --no-cache
jq '.findings[] | select(.kind=="PortScan") | {first_timestamp,last_timestamp,technique}' "$tmp/burst.json"
```

Expected: one `PortScan` with the exact fixture timestamps and `T1046`. Running
again with a config containing `scan_window_minutes = 1` and the same threshold
must not produce that finding.

## 3. Custody and disclaimer

```bash
sha256sum "$tmp/ufw.log"
jq '.custody | {generated_at,hostname,tool_version,config_sha256,disclaimer}' "$tmp/findings.json"
./target/release/ufw-report -l "$tmp/ufw.log" --findings "$tmp/findings.md" --no-cache
```

Expected: the printed digest equals `custody.files[0].sha256`; the disclaimer is
present in both formats; the Markdown contains `## Chain of custody` and the
exact finding timestamps.

## 4. Integrity findings

Run against a range with missing hours and a corrupt `.gz` sibling. Expected:

- `MissingHours` appears in `findings` (Low), while `coverage.missing_hours`
  still reports the count.
- `InputError` names the corrupt file with its reason.
- `summary.total_findings` includes both.

## 5. Quality gates

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -W clippy::pedantic -D warnings
cargo test --all-targets --locked
cargo build --release --locked
```

Expected: all pass; no network access, no `ufw` invocation, no writes outside the
selected outputs and cache directory.
