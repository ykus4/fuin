# Quickstart

Three ways to pack your first APK. All produce the same result — a new, protected APK.
The original is never modified in place.

---

## 1. Web UI

The fastest way to see fuin work.

```bash
git clone https://github.com/ykus4/fuin.git && cd fuin
cp .env.example .env          # set FUIN_API_KEY to any secret string
docker compose up --build
```

Then at <http://localhost:8000>:

1. Enter your API key and press **Save**
2. Drag and drop an `.apk`
3. Watch the live progress bar
4. Click **Download packed APK**

More detail: **[Web UI](../guide/web-ui.md)**

---

## 2. CLI

```bash
fuin-pack pack MyApp.apk MyApp-protected.apk --report
```

With every protection turned on and a real release keystore:

```bash
fuin-pack pack MyApp.apk MyApp-protected.apk \
  --root-detection \
  --emulator-detection \
  --encrypt-strings \
  --verify-signature \
  --keystore release.keystore \
  --key-alias release \
  --store-pass "$STORE_PASS" \
  --key-pass "$KEY_PASS" \
  --report
```

Before committing to a pack, see what would be encrypted:

```bash
fuin-pack analyze MyApp.apk
```

More detail: **[CLI](../guide/cli.md)**

---

## 3. REST API

```bash
export FUIN_API_KEY=your-secret

# Start a pack job
JOB=$(curl -sX POST http://localhost:8000/pack \
  -H "X-API-Key: $FUIN_API_KEY" \
  -F "file=@MyApp.apk" | jq -r .job_id)

# Follow progress (server-sent events)
curl -N "http://localhost:8000/jobs/$JOB/stream?api_key=$FUIN_API_KEY"

# Once done, the job result carries the app_id
APP=$(curl -s "http://localhost:8000/jobs/$JOB" \
  -H "X-API-Key: $FUIN_API_KEY" | jq -r .result.app_id)

# Download
curl -OJ "http://localhost:8000/apps/$APP/download" \
  -H "X-API-Key: $FUIN_API_KEY"
```

More detail: **[REST API](../guide/rest-api.md)**

---

## Verify the result

A packed APK should contain a stub `classes.dex` and the encrypted originals:

```bash
unzip -l MyApp-protected.apk | grep -E 'classes.dex|assets/'
```

```text
classes.dex                     <- the stub, not your code
assets/encrypted.dex            <- your original DEX, AES-256-GCM
assets/key.bin                  <- the key
assets/cert_fingerprint.bin     <- anti-tamper
assets/encrypted_libs/...       <- native libraries, if any
assets/encrypted_res/...        <- user assets, if any
```

Decompiling it should now yield only the stub:

```bash
jadx -d /tmp/out MyApp-protected.apk   # only com.fuin.stub.* is visible
```

!!! warning "Always test on a device before publishing"

    Packing rewrites the manifest and swaps the `Application` class. Install the
    packed APK on a real device or emulator and confirm it launches before you ship
    it. If you enabled root or emulator detection, remember the app will refuse to
    start on a rooted device or emulator — that is the point.

---

## Next steps

- Automate it: **[Gradle plugin](../guide/gradle-plugin.md)** · **[GitHub Action](../guide/github-actions.md)**
- Tune it: **[Configuration](../reference/configuration.md)**
- Understand it: **[Architecture](../reference/architecture.md)**
- Ship it responsibly: **[Threat model](../security/threat-model.md)**
