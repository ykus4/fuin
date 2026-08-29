"""fuin Packer Server (FastAPI) — application assembly.

Routes live in :mod:`fuin.server.routers`:
  GET    /                              — Web UI
  GET    /health                        — Liveness probe (unauthenticated)
  POST   /analyze                       — Preview encryption targets
  POST   /pack                          — Start async pack job → job_id
  GET    /jobs/{job_id}/stream          — SSE progress stream
  GET    /jobs/{job_id}                 — Poll job status
  GET    /apps                          — List packed apps
  GET    /apps/{app_id}/download        — Download packed APK
  GET    /apps/{app_id}/mapping         — Download ProGuard mapping
  POST   /apps/{app_id}/mapping/upload  — Upload ProGuard mapping
  DELETE /apps/{app_id}                 — Delete a packed app
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from fuin.server.config import validate_server_config
from fuin.server.deps import get_engine
from fuin.server.routers import apps, jobs, pack, ui
from fuin.server.routers.ui import STATIC_DIR
from fuin.server.services.cleanup_service import cleanup_old_records, fail_stranded_jobs

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_server_config()
    engine = get_engine()
    # Order matters: reconcile before cleanup, so a job stranded by the last
    # restart is recorded as failed rather than deleted out from under a client
    # that is still polling it.
    fail_stranded_jobs(engine)
    cleanup_old_records(engine)
    yield


app = FastAPI(title="fuin Packer Server", lifespan=lifespan)


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    """Unauthenticated liveness probe for containers and load balancers.

    Deliberately reports nothing but reachability — it is the one route without
    an API key, so it must not disclose configuration.
    """
    return {"status": "ok"}


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(ui.router)
app.include_router(pack.router)
app.include_router(jobs.router)
app.include_router(apps.router)


def run() -> None:
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    uvicorn.run("fuin.server.main:app", host="0.0.0.0", port=8000, reload=False)
