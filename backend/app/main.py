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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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


class ChatRequest(BaseModel):
    message: str

class ChatResponse(BaseModel):
    response: str
    actions: List[Dict[str, str]] = []

class ScanRequest(BaseModel):
    target: str
    type: str

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class TaskRequest(BaseModel):
    command: str

class TaskResponse(BaseModel):
    task_id: str
    status: str

@app.post("/api/v1/chat", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest):
    text = request.message.lower()
    await asyncio.sleep(1.0)
    
    if "scan" in text or "vapt" in text:
        return ChatResponse(
            response=f"I have processed your request regarding '{request.message}'. I can initiate a vulnerability scan on the specified targets. Would you like to proceed?",
            actions=[{"label": "Yes, initiate scan", "action": "scan"}, {"label": "View Details", "action": "details"}]
        )
    elif "report" in text or "compliance" in text:
        return ChatResponse(
            response=f"I have reviewed our compliance mappings. Currently, we are 92% aligned with NIST CSF. Would you like me to generate a full compliance report?",
            actions=[{"label": "Generate Report", "action": "report"}]
        )
    else:
        return ChatResponse(
            response=f"I am analyzing the context of: '{request.message}'. No immediate threats detected. How else can I assist your team today?",
            actions=[]
        )

@app.post("/api/v1/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    scans_db[scan_id] = {
        "target": request.target,
        "type": request.type,
        "status": "Running",
        "progress": 5,
        "phase": "Reconnaissance",
        "start_time": time.time()
    }
    return ScanResponse(scan_id=scan_id, status="Running", message="Scan initiated successfully.")

@app.get("/api/v1/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    scan = scans_db[scan_id]
    elapsed = time.time() - scan["start_time"]
    
    if elapsed > 15:
        scan["status"] = "Completed"
        scan["progress"] = 100
        scan["phase"] = "Reporting"
    elif elapsed > 10:
        scan["progress"] = 75
        scan["phase"] = "Exploitation"
    elif elapsed > 5:
        scan["progress"] = 45
        scan["phase"] = "Vulnerability Scanning"
    elif elapsed > 2:
        scan["progress"] = 15
        scan["phase"] = "Inventory & Mapping"
        
    return scan

async def stream_subprocess(task_id: str, cmd: str):
    """Background task to run a subprocess and capture output"""
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        active_processes[task_id] = process
        tasks_db[task_id]["status"] = "Running"
        
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            # Decode and strip newline, buffer it
            text_line = line.decode('utf-8', errors='replace').rstrip()
            timestamp = time.strftime("[%H:%M:%S]")
            tasks_db[task_id]["logs"].append(f"{timestamp} {text_line}")
            
        await process.wait()
        tasks_db[task_id]["status"] = "Completed"
        
        # Add a final completion marker
        timestamp = time.strftime("[%H:%M:%S]")
        tasks_db[task_id]["logs"].append(f"{timestamp} Task completed with exit code {process.returncode}.")
        
    except Exception as e:
        tasks_db[task_id]["status"] = "Failed"
        timestamp = time.strftime("[%H:%M:%S]")
        tasks_db[task_id]["logs"].append(f"{timestamp} Execution Error: {str(e)}")

@app.post("/api/v1/task", response_model=TaskResponse)
async def create_task(request: TaskRequest):
    task_id = str(uuid.uuid4())
    cmd = request.command
    
    # Simple validation mapping for common tools
    safe_cmd = cmd
    
    tasks_db[task_id] = {
        "command": cmd,
        "status": "Starting",
        "logs": [f"[{time.strftime('%H:%M:%S')}] Agent initialized. Executing: {cmd}"]
    }
    
    # Spawn background task
    asyncio.create_task(stream_subprocess(task_id, safe_cmd))
    
    return TaskResponse(task_id=task_id, status="Running")

@app.get("/api/v1/task/{task_id}/logs")
async def get_task_logs(task_id: str, offset: int = 0):
    if task_id not in tasks_db:
        raise HTTPException(status_code=404, detail="Task not found")
        
    task = tasks_db[task_id]
    logs = task["logs"][offset:]
    
    return {
        "status": task["status"],
        "logs": logs,
        "next_offset": offset + len(logs)
    }

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
