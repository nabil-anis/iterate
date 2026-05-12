from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
import time
import asyncio
import os
from pathlib import Path

app = FastAPI(title="MAESTER Production Execution Engine")
from .routers import router as api_router

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(api_router)
# Global memory for the mock database/process manager
scans_db = {}
tasks_db = {}
active_processes = {}

# --- Static file paths ---
# When running in Docker, static files are at /app/static
# When running locally, they're in the project root (one level up from backend/)
STATIC_DIR = Path("/app/static")
if not STATIC_DIR.exists():
    STATIC_DIR = Path(__file__).resolve().parent.parent.parent  # iterate/ root

# Ensure data directory exists for SQLite
DATA_DIR = Path("/app/data") if Path("/app/data").parent.exists() and os.environ.get("ENVIRONMENT") == "production" else Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)


# (API routes moved to routers.py)


# --- Health check ---
@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

# --- Serve frontend static files ---
# Mount static assets (CSS, JS) — this must come after API routes
if (STATIC_DIR / "styles.css").exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static-assets")

# Catch-all: serve index.html for the root and any non-API path
@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    # Try to serve the exact file first (e.g., styles.css, app.js)
    file_path = STATIC_DIR / full_path
    if full_path and file_path.is_file():
        return FileResponse(str(file_path))
    # Default to index.html
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    raise HTTPException(status_code=404, detail="Frontend not found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
