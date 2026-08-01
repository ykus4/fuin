# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-08-01

A large release. The Python package is reorganised, the web service moves behind
an extra, and several latent bugs are fixed. **Read the migration notes below
before upgrading.**

### Breaking

- **`pip install fuin` no longer installs the server.** The base install is the
  packer alone — `cryptography` and `python-dotenv`, down from 12 packages.
  Install `fuin[server]` to get `fuin-server`.
- **Module paths changed.** The flat package is grouped by concern:

  | Before | After |
  |---|---|
  | `fuin.crypto` | `fuin.encryption.aes` |
  | `fuin.string_encrypt` | `fuin.encryption.dex_strings` |
  | `fuin.native_lib` | `fuin.encryption.native_libs` |
  | `fuin.resource_encrypt` | `fuin.encryption.resources` |
  | `fuin.apk` | `fuin.apk.repack` (or `fuin.apk`) |
  | `fuin.signing`, `fuin.zipalign`, `fuin.keystore`, `fuin.stub_dex` | `fuin.apk.*` |
  | `fuin.android_tools` | `fuin.apk.tools` |
  | `fuin.manifest.patch_manifest` | `fuin.apk.patch_manifest` |
  | `fuin.manifest` (byte level) | `fuin.axml.patcher` |
  | `fuin.apk_info` | `fuin.axml.info` |
  | `fuin.analyze`, `fuin.report` | `fuin.reporting.*` |
  | `fuin._constants` | `fuin.contract` (+ `fuin.axml.constants`, `fuin.apk.constants`) |
  | `fuin.integrity` | removed — use `fuin.apk.extract_cert_fingerprint` |
  | `fuin.server.models` | `fuin.server.schemas` |
- **Gradle composite-build path changed.** `includeBuild("path/to/fuin/gradle-plugin")`
  becomes `includeBuild("path/to/fuin/jvm/gradle-plugin")`.
- `run_pipeline` returns a `PackedOutput` instead of a `(path, sha256, report)` tuple.
- `PipelineOptions` is removed; use `PackOptions`.
- The Pydantic `PackResult` is renamed `PackedApp`, to stop colliding with the
  packer's `PackResult` dataclass. `RegisterAppResponse` is removed (unused).
- Protection options are now tri-state. Omitting `--root-detection`,
  `--emulator-detection`, `--encrypt-strings`, `--verify-signature` or
  `--no-strict-manifest-patch` defers to the matching `FUIN_*` variable; passing
  one always wins. Previously an explicit `False` could be overridden by the
  environment.

### Fixed

- **The published wheel could not pack.** `assets/stub.dex` sat outside the
  package directory and was never included, so `pip install fuin` had no stub to
  inject. It now ships inside the wheel.
- **The Docker image did not start.** The build never installed the project, so
  the `fuin-server` console script did not exist and the container exited
  immediately.
- **Settings were captured at import time**, so `FUIN_*` changes needed a process
  restart, and every pipeline test wrote packed APKs into the repository instead
  of a temp directory.
- **`package_name` could be read from the wrong resource ID**, returning an
  unrelated string-pool entry on APKs carrying a `versionCode`.
- `version_code` was always `None` — initialised and never assigned.
- **Concurrent pack jobs clobbered each other** through a single shared
  `.pending.apk` scratch path.
- `pipeline.py` re-listed all 13 `PackOptions` fields to override one, silently
  dropping any field added later.
- The in-memory job store grew without bound, retaining every finished job's full
  result for the process lifetime.
- Detached asyncio tasks were created without holding a reference and could be
  garbage-collected mid-flight.
- A DEX between 44 and 63 bytes raised `struct.error` instead of being skipped
  (off-by-one in the header bounds check).
- `reset_engine` dropped the engine without disposing its connection pool.
- Dead code removed from the AXML patcher, including an authoring note left in a
  shipped source file.

### Added

- **Documentation site** at <https://ykus4.github.io/fuin> — 14 pages covering
  installation, all five interfaces, configuration, the API, architecture,
  security and development. Built with `--strict` in CI and deployed to GitHub
  Pages.
- `FUIN_MAX_MAPPING_MB` for the ProGuard mapping upload limit, previously
  hardcoded at 50 MB.
- Tests for `signing` and `string_encrypt`, neither of which had any coverage.
- mypy, running clean over the package, in CI and pre-commit.
- CI now tests Python 3.12, 3.13 and 3.14 (the Docker image ships 3.14 and had
  never been tested), measures coverage, runs the Docker image rather than only
  building it, exercises Alembic upgrade/downgrade and checks the migrated schema
  against the models, and verifies a packer-only wheel install can pack an APK.

### Changed

- Adopted a src layout (`src/fuin/`).
- `stub/` and `gradle-plugin/` are grouped under `jvm/`.
- The two AXML parsers — one in the inspector, one in the patcher — are unified
  into `fuin.axml`. PKCS12 handling, external-tool invocation and ZIP-copy loops
  are likewise deduplicated.
- The server gains router, repository and settings layers; `main.py` drops from
  286 lines to app assembly only.
- `action.yml` no longer installs the dev dependency group, and no longer breaks
  workspace-relative input/output paths.
- README trimmed from 446 lines to an entry point, with the content moved to the
  documentation site.

## [1.1.2] - 2026-05-09

See the [release notes](https://github.com/ykus4/fuin/releases/tag/v1.1.2).

## [1.1.1] - 2026-05-07

See the [release notes](https://github.com/ykus4/fuin/releases/tag/v1.1.1).

## [1.1.0] - 2026-05-07

See the [release notes](https://github.com/ykus4/fuin/releases/tag/v1.1.0).

## [1.0.0] - 2026-05-02

Initial release.

[2.0.0]: https://github.com/ykus4/fuin/compare/v1.1.2...v2.0.0
[1.1.2]: https://github.com/ykus4/fuin/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/ykus4/fuin/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/ykus4/fuin/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ykus4/fuin/releases/tag/v1.0.0
