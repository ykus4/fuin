"""The bundled single-page web UI."""

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

STATIC_DIR = Path(__file__).parent.parent / "static"

router = APIRouter()


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def serve_ui():
    html_path = STATIC_DIR / "index.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI not found")
    return HTMLResponse(html_path.read_text())
