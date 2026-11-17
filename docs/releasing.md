# Releasing ufw-report

Releases are built and published by GitHub Actions. A tag push is the only
manual trigger; nothing is uploaded from a workstation.

## Versioning

- Versions follow Semantic Versioning. Before `1.0.0`, minor releases may
  include breaking CLI or output changes.
- The tag must be `v<version>` and must match the `version` field in
  `Cargo.toml`. For example, `v0.2.0` requires `version = "0.2.0"`.
- The release workflow fails before building when the tag and the package
  version disagree.

## Supported targets

| Target | Runner | Extra tooling | Notes |
|--------|--------|---------------|-------|
| `x86_64-unknown-linux-gnu` | `ubuntu-22.04` | none | Lower glibc floor than `ubuntu-latest` |
| `aarch64-unknown-linux-gnu` | `ubuntu-22.04` | `gcc-aarch64-linux-gnu` | ARM64 servers and Raspberry Pi |
| `x86_64-unknown-linux-musl` | `ubuntu-22.04` | `musl-tools` | Fully static; recommended for air-gapped systems |

GNU binaries are linked dynamically and require a compatible glibc. Musl
binaries are static and do not depend on the host's C library.

## Artifacts

Each target produces:

```
ufw-report-v<version>-<target>.tar.gz
ufw-report-v<version>-<target>.tar.gz.sha256
```

The tarball contains:

```
ufw-report-v<version>-<target>/
├── ufw-report
├── README.md
├── LICENSE
└── CHANGELOG.md
```

Checksums are generated with `sha256sum` inside the `dist/` directory, so users
can verify with:

```bash
sha256sum -c ufw-report-v0.2.0-x86_64-unknown-linux-musl.tar.gz.sha256
```

## Release checklist

1. Update `CHANGELOG.md` with the new version and date.
2. Bump `version` in `Cargo.toml`.
3. Run `cargo update` only if dependencies changed, then commit the updated
   `Cargo.lock`.
4. Run the local checks:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets --all-features -- -W clippy::pedantic -D warnings
   cargo test --all-targets --locked
   cargo build --release --locked
   ```

5. Merge the release commit to `main` and confirm CI is green.
6. Create and push an annotated tag:

   ```bash
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

7. Watch the **Release** workflow. It verifies the tag, builds the three
   targets, packages the tarballs, and publishes the GitHub Release.
8. Download one artifact and verify the checksum and the binary:

   ```bash
   ./ufw-report --version
   ```

9. If a target fails, fix the workflow or the code and publish a patch release
   instead of re-pointing the tag.

## Manual fallback

If Actions is unavailable, build on a compatible host:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl
```

Then package the staged directory exactly as the workflow does, upload the
tarball and its checksum, and verify the download before announcing it.

## Future work

- Signed releases (for example, `cosign` or `minisign`)
- `.deb` packages built from the tarballs
- PPA/Launchpad publication
- `cargo install ufw-report` via crates.io

These are tracked in [`roadmap.md`](roadmap.md) and are not part of the current
release process.
