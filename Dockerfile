# syntax=docker/dockerfile:1

FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Dependencies first, in their own layer, so source edits don't re-resolve them.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --extra server --no-install-project

COPY src/ src/
COPY migrations/ migrations/
COPY alembic.ini ./

# Install the project itself — without this the `fuin-server` console script
# is never created and the container exits immediately on start.
RUN uv sync --frozen --no-dev --extra server

ENV FUIN_PACKED_DIR=/data/packed_apks
ENV FUIN_DATABASE_URL=sqlite:////data/fuin.db

VOLUME ["/data"]
EXPOSE 8000

CMD ["uv", "run", "--no-sync", "fuin-server"]
