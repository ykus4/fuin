#!/bin/sh
# Bring the database schema up to date, then serve.
#
# Before this existed the container went straight to `fuin-server`, so the
# schema came from `create_all` and `alembic_version` was never stamped. Any
# volume from such a deployment therefore has the tables but no migration
# history, and a plain `alembic upgrade head` would try to create them again
# and fail. Stamp those first; a genuinely empty database is stamped by the
# upgrade itself.
set -eu

if uv run --no-sync python - <<'PY'
import sys
from sqlalchemy import create_engine, inspect

from fuin.server.config import get_server_settings

inspector = inspect(create_engine(get_server_settings().database_url))
tables = set(inspector.get_table_names())
# Pre-Alembic: application tables present, migration history absent.
sys.exit(0 if "apps" in tables and "alembic_version" not in tables else 1)
PY
then
    echo "fuin: existing schema predates Alembic — stamping it as current"
    uv run --no-sync alembic stamp head
fi

uv run --no-sync alembic upgrade head

exec uv run --no-sync fuin-server
