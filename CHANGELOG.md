# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Correctness release. Several protections were not doing anything, and nothing
in the suite noticed because the assertions checked shape rather than outcome.
No configuration changes are required.

### Fixed

- **The pure-Python `zipalign` never worked.** Its local-file-header format
  string unpacked 11 fields into 10 names, so it raised `ValueError` on the
  first entry of every input. Nobody hit it because the tests ran the Android
  SDK binary whenever one was on `PATH` — which is the case on developer
  machines and on GitHub runners, but not for `pip install fuin` without the
  SDK, the setup the docs advertise. Two further bugs sat behind it: the
  padding calculation ignored any existing extra field, and the central
  directory was copied verbatim, leaving every entry offset stale once padding
  shifted the entries. The aligner is rewritten against the central directory
  and now rejects ZIP64 archives and already-signed APKs instead of silently
  corrupting them.
- **The pure-Python v2 signature was never valid.** The APK Signing Block size
  fields were 8 bytes too large, so `apksigner` could not find the block at all
  and reported the APK as v2-unsigned; behind that, the signers sequence was
  missing its outer length prefix, the certificate sequence carried one prefix
  too many, the additional-attributes sequence declared a zero-length
  attribute, the content digest was computed per section instead of over one
  flat chunk list, and the EOCD was digested with its central-directory offset
  zeroed rather than left pointing at the signing block. Output now verifies
  with `apksigner verify`, which the suite asserts.
- **v1 signing destroyed the alignment `zipalign` had just applied**, because it
  rebuilds the archive through `zipfile`. The fallback path re-aligns between
  v1 and v2.
- **`X-Android-APK-Signed: 2`** is now written into the `.SF`, so a stripped v2
  block cannot silently downgrade verification to v1.
- **`exclude_files` deleted the native libraries it excluded.** The encryptor
  returned a blanket `^lib/.*\.so$` strip pattern regardless of what it had
  actually encrypted, so an excluded `.so` was neither encrypted nor shipped.
- **The resource-map chunk type was wrong** (`0x00180002`, against Android's
  `0x00080180`), so fuin parsed zero resource IDs and reported `min_sdk`,
  `target_sdk`, `version_code`, `version_name` and permissions as empty for
  every real APK. The test fixture emitted the same wrong value and so agreed
  with the bug.
- **A malformed manifest could exhaust memory.** `string_count` is an
  attacker-controlled `u32` and was used directly as a loop bound, so a
  few-hundred-byte upload could claim `0xFFFFFFFF` strings. It is now bounded by
  the buffer. Reachable from `POST /pack`.
- **`patch_axml` raised on truncated input** while formatting the warning that
  the input was truncated.
- **The fallback manifest patcher could ship a corrupt manifest.** When the
  replacement class name differed in length it did a raw byte `replace`, which
  shifts every AXML offset, and still reported success — so `strict_manifest_patch`
  passed. It now declines and reports failure.
- **Duplicate ZIP entries were silently collapsed** onto the last copy, because
  entries were read by name rather than through their `ZipInfo`. Signing now
  rejects duplicate names outright.
- **A genuine `apksigner` failure was mistaken for a missing JRE** — the check
  searched stderr for `"java"`, which matches every Java stack trace — and
  quietly fell through to the fallback signer.
- **A failure to read the signing certificate disabled anti-tamper silently.**
  It is now only tolerated for the generated debug keystore.
- **The pack report said "Encrypted DEX files: 0"** for single-DEX apps: it
  derived the count from removed entries, and `classes.dex` comes back as the
  stub.
- `axml/` no longer opens ZIP files, restoring the `packer` → `apk` → `axml`
  layering the docs describe. `get_apk_info` moves to `fuin.apk.info` and its
  error path returns the same keys as its success path.
- Encrypted asset names use the full SHA-256 digest instead of a 64-bit prefix,
  which was cheap to collide and silently dropped one of the colliding assets.

### Security

- **Webhook URLs are validated.** The per-request `webhook_url` was POSTed to
  unchecked, so any authenticated caller could reach cloud instance metadata or
  internal hosts. Targets must now be `https` (`FUIN_WEBHOOK_ALLOW_HTTP` opts
  into plain http) and resolve entirely to public addresses.
- **Upload limits are enforced while reading.** `POST /analyze` had no limit at
  all and `POST /pack` checked only after the whole body was in memory.
- **The API key is compared with `secrets.compare_digest`** rather than `==`.
- **Job errors no longer return raw exception text**, which carried server temp
  and keystore paths.
- **The container runs as a non-root user** and applies migrations before
  serving.
- External build tools run with a timeout, so a wedged `apksigner` cannot pin a
  worker forever.

### Added

- `GET /health` — unauthenticated liveness probe, plus a Docker `HEALTHCHECK`.
- 16 KiB page alignment for uncompressed `lib/**/*.so`, for Android 15 devices.
  Opt in via `zipalign(..., so_alignment=PAGE_ALIGNMENT)`.
- Jobs left `running` by a restart are marked failed at startup instead of
  being reported as in progress forever.
- SQLite connections enable WAL, a busy timeout and foreign keys;
  `FUIN_DATABASE_URL` now works for non-SQLite backends.
- An SSE subscriber that connects after a job finished receives the terminal
  state instead of blocking forever, and progress events are marshalled onto
  the event loop rather than pushed onto an `asyncio.Queue` from a worker
  thread.

### Changed

- `inject_encrypted_dex` takes an `InjectedAssets` dataclass instead of
  fourteen keyword arguments.
- `encrypt_native_libs` / `encrypt_resources` return `EncryptedEntries` instead
  of an untyped `dict`, and share one entry reader.
- Entry selection (`is_native_lib`, `is_user_asset`) lives in `fuin.contract`,
  so `analyze` and `pack` cannot disagree about what gets encrypted.
- New `fuin.apk.zip_format` module holds byte-level ZIP record parsing, shared
  by signing and alignment.

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
