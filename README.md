<div align="center">

<img src="docs/logo.png" alt="fuin logo" width="600">

**Android APK Packer — protect bytecode, block cheating, resist reverse engineering**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/)
[![CI](https://github.com/ykus4/fuin/actions/workflows/ci.yml/badge.svg)](https://github.com/ykus4/fuin/actions/workflows/ci.yml)

**[📖 Documentation](https://ykus4.github.io/fuin)** ·
[Quickstart](https://ykus4.github.io/fuin/getting-started/quickstart/) ·
[Configuration](https://ykus4.github.io/fuin/reference/configuration/) ·
[Threat model](https://ykus4.github.io/fuin/security/threat-model/)

</div>

---

fuin takes a finished APK and produces a new, protected one. DEX bytecode, native
libraries (`.so`) and assets are encrypted with AES-256-GCM; a small stub decrypts
them in memory at launch. Anti-tamper, root detection and emulator blocking raise the
bar against runtime instrumentation tools like Frida and Xposed.

Works with Unity, Flutter and standard Android apps. No source changes. No network at
runtime. Fully offline.

![fuin demo](docs/demo.gif)

## Quick start

```bash
git clone https://github.com/ykus4/fuin.git && cd fuin
cp .env.example .env          # set FUIN_API_KEY to any secret string
docker compose up --build
```

Open <http://localhost:8000>, drag and drop your APK, done.

Or from the command line:

```bash
fuin-pack pack MyApp.apk MyApp-protected.apk --report
```

→ **[Full quickstart](https://ykus4.github.io/fuin/getting-started/quickstart/)**

## Documentation

| | |
|---|---|
| [Installation](https://ykus4.github.io/fuin/getting-started/installation/) | Docker, pip, local development setup |
| [CLI](https://ykus4.github.io/fuin/guide/cli/) · [REST API](https://ykus4.github.io/fuin/guide/rest-api/) · [Web UI](https://ykus4.github.io/fuin/guide/web-ui/) | Everyday usage |
| [Gradle plugin](https://ykus4.github.io/fuin/guide/gradle-plugin/) · [GitHub Action](https://ykus4.github.io/fuin/guide/github-actions/) | Build integration |
| [Configuration](https://ykus4.github.io/fuin/reference/configuration/) | Every environment variable |
| [Architecture](https://ykus4.github.io/fuin/reference/architecture/) | Pack-time and runtime pipelines |
| [Protection layers](https://ykus4.github.io/fuin/security/protection-layers/) · [Threat model](https://ykus4.github.io/fuin/security/threat-model/) | What it does and does not protect against |
| [Development](https://ykus4.github.io/fuin/development/) | Tests, linting, migrations, contributing |
| [Changelog](https://ykus4.github.io/fuin/changelog/) | Release history and migration notes |

> [!WARNING]
> The AES key is bundled inside the APK by design. That defeats static analysis, not
> an attacker who controls the device. Read the
> [threat model](https://ykus4.github.io/fuin/security/threat-model/) before shipping.

## License

[MIT](LICENSE) © 2026 yotti
