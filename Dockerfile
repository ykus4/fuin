# syntax=docker/dockerfile:1

# ── Stage 1: build stub DEX ───────────────────────────────────────────────
FROM eclipse-temurin:17-jdk AS stub-builder

# Install Android build-tools for d8
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://dl.google.com/android/repository/build-tools_r34-linux.zip" \
      -o /tmp/build-tools.zip \
    && unzip -q /tmp/build-tools.zip -d /tmp/bt \
    && mv /tmp/bt/android-14 /opt/android-build-tools \
    && rm -rf /tmp/bt /tmp/build-tools.zip

ENV ANDROID_HOME=/opt/android-sdk
ENV PATH="/opt/android-build-tools:$PATH"

WORKDIR /stub
COPY stub/ .

RUN ./gradlew :app:assembleRelease --no-daemon -q \
    && /opt/android-build-tools/d8 \
         --output /stub-dex \
         --min-api 24 \
         app/build/outputs/aar/app-release.aar \
    || true

# If d8 on AAR doesn't work directly, extract classes.jar first
RUN if [ ! -f /stub-dex/classes.dex ]; then \
      unzip -p app/build/outputs/aar/app-release.aar classes.jar > /tmp/classes.jar \
      && /opt/android-build-tools/d8 --output /stub-dex --min-api 24 /tmp/classes.jar; \
    fi


# ── Stage 2: runtime ──────────────────────────────────────────────────────
FROM python:3.13-slim

# Install zipalign + apksigner (Android build-tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl unzip openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://dl.google.com/android/repository/build-tools_r34-linux.zip" \
      -o /tmp/build-tools.zip \
    && unzip -q /tmp/build-tools.zip -d /tmp/bt \
    && mv /tmp/bt/android-14 /opt/android-build-tools \
    && rm -rf /tmp/bt /tmp/build-tools.zip

ENV ANDROID_HOME=/opt/android-sdk
ENV PATH="/opt/android-build-tools:$PATH"

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Install Python dependencies (cached layer)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy source
COPY fuin/ fuin/
COPY server/ server/

# Copy pre-built stub DEX from stage 1
COPY --from=stub-builder /stub-dex/classes.dex fuin/stub.dex

ENV FUIN_PACKED_DIR=/data/packed_apks
ENV FUIN_DATABASE_URL=sqlite:////data/fuin.db

VOLUME ["/data"]
EXPOSE 8000

CMD ["uv", "run", "--no-sync", "fuin-server"]
