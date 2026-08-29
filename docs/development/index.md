# Development

## Setup

```bash
git clone https://github.com/ykus4/fuin.git && cd fuin
uv sync --all-extras          # --all-extras: the tests need the server deps
uv run pre-commit install
```

`uv sync` alone installs the packer only. Use `--all-extras`.

See **[Installation](../getting-started/installation.md#local-development-setup)** for
the Android build-tools and JDK setup, both optional.

---

## Everyday commands

| Command | What it does |
|---|---|
| `uv run pytest` | Run the test suite |
| `uv run pytest --cov` | With a coverage report |
| `uv run ruff check src/ tests/` | Lint |
| `uv run ruff format src/ tests/` | Format |
| `uv run mypy` | Type-check |
| `uv run pre-commit run --all-files` | Everything the hooks run |
| `uv run mkdocs serve` | Preview this site at <http://localhost:8000> |

Warnings are errors in the test suite (`filterwarnings = ["error"]`), so a new
`DeprecationWarning` or `ResourceWarning` fails the build rather than accumulating.

---

## Layout

fuin uses a **src layout**: the package lives at `src/fuin/`, so tests run against the
installed package rather than the source tree, and packaging mistakes surface in CI.
The `fuin` directory itself is the import name — modules cannot move up to `src/`
directly, or every subpackage would become a top-level import.

The core packer is grouped by concern rather than kept flat:

| Package | Owns |
|---|---|
| `axml/` | Android Binary XML, byte level only — no ZIP, no filesystem |
| `apk/` | ZIP I/O, signing, alignment, the Android SDK toolchain |
| `encryption/` | AES, DEX strings, native libraries, assets |
| `reporting/` | Read-only views: analysis and the pack diff |
| `contract.py` | The asset paths and entry selectors shared with the Kotlin stub |

Within `apk/`, `zip_format.py` parses raw ZIP records (EOCD, central directory,
local headers) and `zip_tools.py` works through `zipfile`. Alignment and v2
signing both need the former, because `zipfile` will not tell you where the
central directory physically sits.

Dependencies run downward only: `packer.py` → `apk/` → `axml/`. If you find yourself
importing `apk` from `axml`, the code probably belongs on the other side of that line.

`src/fuin/assets/stub.dex` is committed and ships inside the wheel. That is why
`pip install fuin` can pack without an Android SDK — see
[Architecture](../reference/architecture.md#repository-layout).

---

## Tests

```text
tests/
├── fixtures/            # importable builders — not conftest
│   ├── axml.py          # hand-rolled binary AXML
│   └── apk.py           # minimal APK (ZIP)
├── conftest.py          # fixtures only
├── test_apk.py          # injection + alignment, including the pure-Python aligner
├── test_axml_malformed.py  # untrusted-manifest handling
├── test_crypto.py
├── test_manifest.py
├── test_pipeline.py     # end-to-end pack
├── test_server.py       # FastAPI endpoints, including a job run to completion
├── test_signing.py      # v1/v2 signing, cert fingerprint
├── test_string_encrypt.py
└── test_webhooks.py     # webhook target validation (SSRF)
```

### Exercise the fallbacks

`zipalign` and `sign_apk` prefer the Android SDK binaries and fall back to
pure-Python implementations. A test that calls the public function therefore
tests whichever path this machine happens to have — and on a developer machine
with `ANDROID_HOME` set, that is never the fallback. Both fallbacks shipped
broken for exactly that reason.

Call `_zipalign_py` / `_sign_v1` / `_sign_v2` directly when the fallback is what
you mean to test, and gate any test of the real binaries on
`find_build_tool(...) is None`.

Builders live in `tests/fixtures/` rather than `conftest.py` on purpose: pytest
treats conftest specially, and importing helpers from it leaks that into anything
else that needs them, including CI.

The AXML builder is deliberately **independent** of `fuin.axml`. A builder sharing the
parser's code could not catch the parser being wrong.

### Writing tests

Prefer asserting on behaviour over shape. `assert zipfile.is_zipfile(out)` passes for
almost any zip; assert on the entries, the digests and the header fields that matter.

For refactors with no intended behaviour change, differential testing beats the
suite. Check the previous revision out into a worktree and compare outputs directly:

```bash
git worktree add --detach /tmp/before <ref>
# run both, compare hashes of the artefacts
git worktree remove /tmp/before --force
```

---

## Type checking

mypy runs over `src/fuin` and must stay clean. Settings are deliberately moderate —
the codebase was annotated but never checked, so the configuration starts at a level
that passes today and should tighten as untyped edges get annotated.

SQLAlchemy models use 2.0 `Mapped[...]` annotations. Adding a column with a bare
`Column(...)` assignment will type every read of it as `Column[str]` and break call
sites downstream.

---

## Database migrations

Models live in `src/fuin/server/database.py`; migrations in `migrations/versions/`.

```bash
uv run alembic revision --autogenerate -m "describe the change"
uv run alembic upgrade head
uv run alembic downgrade -1          # always test the way back
```

CI runs `upgrade → downgrade → upgrade` and asserts the migrated schema matches
`Base.metadata`. The test suite builds its schema with `create_all`, so without that
job migrations could silently drift from the models.

---

## Rebuilding the stub

```bash
cd jvm/stub && ./gradlew :app:assembleRelease
```

`fuin.stub_dex` extracts `classes.jar` from the AAR and converts it with `d8`. The
result is cached to `src/fuin/assets/stub.dex`. Commit it when the stub changes.

Point [`FUIN_STUB_DEX`](../reference/configuration.md) at a file to override it
without rebuilding.

---

## Docs

This site is MkDocs Material. Pages live in `docs/`, navigation in `mkdocs.yml`.

```bash
uv run mkdocs serve            # live reload
uv run mkdocs build --strict   # what CI runs; warnings are errors
```

`--strict` fails on broken internal links, so a renamed page cannot silently orphan
its references.

---

## CI

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Purpose |
|---|---|
| Lint & format | ruff check, ruff format, mypy |
| Tests | pytest on Python 3.12, 3.13 and 3.14, with coverage |
| Packer-only install | Builds the wheel, installs it with no extras, packs an APK |
| Alembic migrations | upgrade → downgrade → upgrade, plus a schema-drift check |
| Docs | `mkdocs build --strict` |
| Gradle plugin | Builds the plugin |
| Android stub | Builds the stub AAR |
| Docker build | Builds the image, starts it, and serves a request |

The Python matrix includes 3.14 because that is what the Docker image ships.

The packer-only job guards two regressions this repository has already had:
`stub.dex` missing from the wheel, and server dependencies leaking into the base
install.

---

## Releasing

fuin is not published to PyPI yet. The Docker image is built and pushed by
`.github/workflows/docker.yml`.

When adding a release process, note that `action.yml` currently installs from the
repository checkout. It can become a thin wrapper over a published wheel once one
exists.
