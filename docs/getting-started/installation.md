# Installation

fuin ships as two things: a **packer** (`fuin-pack`, a CLI) and a **server**
(`fuin-server`, a FastAPI service with a web UI). The server is an optional extra, so
CLI users are not made to install FastAPI, SQLAlchemy and friends.

=== "Docker (recommended)"

    Runs the server with the Android build-tools already inside the image — nothing
    to install on the host.

    ```bash
    git clone https://github.com/ykus4/fuin.git && cd fuin
    cp .env.example .env          # set FUIN_API_KEY to any secret string
    docker compose up --build
    ```

    Open <http://localhost:8000>.

    !!! note "First build is slow"

        The initial build downloads Android build-tools and compiles the stub DEX.
        Later starts are instant, and packed APKs persist in a named Docker volume.

=== "pip / uv (packer only)"

    ```bash
    uv tool install fuin          # or: pipx install fuin
    fuin-pack pack in.apk out.apk
    ```

    This installs the packer alone — `cryptography` and `python-dotenv`, nothing else.
    The pre-built stub DEX ships inside the wheel, so packing works without an
    Android SDK.

    !!! info "Not yet on PyPI"

        fuin is not published to PyPI yet. Until it is, install from a checkout:
        `uv tool install .`

=== "pip / uv (with the server)"

    ```bash
    uv tool install 'fuin[server]'
    FUIN_API_KEY=... fuin-server
    ```

    The `server` extra adds FastAPI, uvicorn, SQLAlchemy, Alembic, pydantic,
    httpx and python-multipart.

---

## Requirements

| | |
|---|---|
| **Python** | 3.12 or newer |
| **Android build-tools** | Optional. Used for `zipalign` and `apksigner` when present; fuin falls back to a pure-Python implementation of both. |
| **JDK 17** | Only needed to rebuild the stub DEX from source. |

fuin discovers build-tools from `PATH`, then from `$ANDROID_HOME/build-tools/<latest>`.
No `PATH` changes are needed if you install the SDK in the usual place.

!!! tip "The pure-Python fallback is for smoke tests"

    Release pipelines should have real `apksigner` available and set
    [`FUIN_VERIFY_SIGNATURE=true`](../reference/configuration.md) so the packed APK is
    verified after signing.

---

## Local development setup

For working on fuin itself, or running the server without Docker.

=== "macOS"

    ```bash
    # Toolchain
    curl -LsSf https://astral.sh/uv/install.sh | sh
    brew install openjdk@17

    # Android build-tools 34 (zipalign + apksigner)
    mkdir -p ~/android-sdk/build-tools
    curl -L "https://dl.google.com/android/repository/build-tools_r34-macosx.zip" -o /tmp/bt.zip
    unzip -q /tmp/bt.zip -d /tmp/bt
    mv /tmp/bt/android-14 ~/android-sdk/build-tools/34.0.0

    # Build the stub DEX (one-time; a pre-built one is committed)
    cd jvm/stub && ./gradlew :app:assembleRelease && cd ../..

    # Install everything, including the server extra
    uv sync --all-extras
    cp .env.example .env          # set FUIN_API_KEY
    uv run fuin-server
    ```

=== "Linux"

    ```bash
    curl -LsSf https://astral.sh/uv/install.sh | sh
    sudo apt-get install -y openjdk-17-jdk

    mkdir -p ~/android-sdk/build-tools
    curl -L "https://dl.google.com/android/repository/build-tools_r34-linux.zip" -o /tmp/bt.zip
    unzip -q /tmp/bt.zip -d /tmp/bt
    mv /tmp/bt/android-14 ~/android-sdk/build-tools/34.0.0

    cd jvm/stub && ./gradlew :app:assembleRelease && cd ../..

    uv sync --all-extras
    cp .env.example .env
    uv run fuin-server
    ```

`uv sync --all-extras` is what you want for development — plain `uv sync` installs the
packer only, and the tests need the server dependencies.

See **[Development](../development/index.md)** for the test, lint and type-check
workflow.

---

## Next steps

- **[Quickstart](quickstart.md)** — pack your first APK
- **[Configuration](../reference/configuration.md)** — every environment variable
