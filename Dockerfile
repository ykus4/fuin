# syntax=docker/dockerfile:1

FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Dependencies first, in their own layer, so source edits don't re-resolve them.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --extra server --no-install-project

COPY src/ src/
COPY migrations/ migrations/
COPY alembic.ini docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

# Install the project itself — without this the `fuin-server` console script
# is never created and the container exits immediately on start.
RUN uv sync --frozen --no-dev --extra server

ENV FUIN_PACKED_DIR=/data/packed_apks
ENV FUIN_DATABASE_URL=sqlite:////data/fuin.db

# The service parses attacker-supplied ZIP, DEX and AXML. Do not do that as
# uid 0 with /data mounted.
RUN useradd --system --create-home --uid 10001 fuin \
    && mkdir -p /data \
    && chown -R fuin:fuin /data /app
USER fuin

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"]

# Migrations run in the entrypoint. Without this the container depended on
# create_all, alembic_version was never stamped, and no migration could ever
# apply to an existing volume.
CMD ["./docker-entrypoint.sh"]
