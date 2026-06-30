# syntax=docker/dockerfile:1

FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY fuin/ fuin/
COPY assets/ assets/
COPY migrations/ migrations/
COPY alembic.ini ./

ENV FUIN_PACKED_DIR=/data/packed_apks
ENV FUIN_DATABASE_URL=sqlite:////data/fuin.db

VOLUME ["/data"]
EXPOSE 8000

CMD ["uv", "run", "--no-sync", "fuin-server"]
