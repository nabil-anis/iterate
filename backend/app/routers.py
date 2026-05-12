from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import uuid
import time
import asyncio

router = APIRouter()

# In‑memory state stores (simulating Redis for this demo)
findings_db: Dict[str, Dict[str, Any]] = {}
alerts_db: Dict[str, Dict[str, Any]] = {}
reports_db: Dict[str, Dict[str, Any]] = {}
notifications_db: List[Dict[str, Any]] = []
scans_db: Dict[str, Dict[str, Any]] = {}
tasks_db:Dict[str, Dict[str, Any]] = {}
threat_intel_db: List[Dict[str, Any]] = []
soc_events: List[Dict[str, Any]] = []

# --- Initial Demo Data ---
def seed_data():
    # Findings
    for i in range(12):
        fid = f"ST-{900 + i}"
        findings_db[fid] = {
            "id": fid,
            "title": ["Log4j RCE", "SQL Injection", "Exposed AWS Key", "Weak SSH Config", "Outdated Kernel"][i % 5],
            "severity": ["critical", "high", "medium", "low"][i % 4],
            "status": "open" if i % 3 != 0 else "remediated",
            "asset": ["web-prod-01", "api-gateway", "db-cluster", "jenkins-ci"][i % 4],
            "tool": ["Nuclei", "Nmap", "Snyk", "ZAP"][i % 4],
            "cvss": [9.8, 8.5, 7.2, 5.0][i % 4],
            "description": "Potential vulnerability detected during automated scanning.",
            "created_at": time.time() - (i * 3600),
            "updated_at": time.time(),
        }
    
    # Alerts
    for i in range(3):
        aid = str(uuid.uuid4())[:8]
        alerts_db[aid] = {
            "id": aid,
            "title": ["Brute Force Attempt", "Malicious IP Connection", "Data Exfiltration"][i],
            "severity": ["high", "critical", "medium"][i],
            "status": "active",
            "source": ["Okta", "Palo Alto", "CrowdStrike"][i],
            "created_at": time.time() - (i * 600),
        }
    
    # Notifications
    notifications_db.extend([
        {"id": "n1", "message": "New critical finding on web-prod-01", "read": False, "timestamp": time.time()},
        {"id": "n2", "message": "VAPT Scan Completed", "read": False, "timestamp": time.time() - 3600},
    ])

    # Threat Intel
    threat_intel_db.extend([
        {"id": "1", "ioc_type": "ip", "value": "185.23.44.12", "description": "Known C2 server", "severity": "high"},
        {"id": "2", "ioc_type": "domain", "value": "phish-maester.com", "description": "Active phishing campaign", "severity": "medium"},
        {"id": "3", "ioc_type": "hash", "value": "a1b2c3d4...", "description": "Emotet payload", "severity": "critical"},
    ])

    # Initial SOC Events
    soc_events.append({"id": "e1", "type": "INFO", "message": "Monitoring traffic on Gateway-Alpha", "timestamp": time.time()})

seed_data()

# SOC Event Generator
async def soc_event_loop():
    while True:
        await asyncio.sleep(8)
        event_type = ["INFO", "WARN", "CRITICAL"][int(time.time() % 3)]
        msg = [
            "Connection spike detected from 185.x.x.x (RU)",
            "Brute force attempt detected on SSH service (Admin)",
            "New asset discovered: web-stage-02",
            "Credential stuffing attempt on VPN gateway",
            "Port scan detected from local subnet"
        ][int(time.time() % 5)]
        soc_events.append({
            "id": str(uuid.uuid4())[:8],
            "type": event_type,
            "message": msg,
            "timestamp": time.time()
        })
        if len(soc_events) > 50: soc_events.pop(0)

@router.on_event("startup")
async def startup_event():
    asyncio.create_task(soc_event_loop())

@router.get("/api/v1/soc/events")
async def get_soc_events():
    return soc_events[::-1] # Newest first

# ---------- Dashboard ----------
class DashboardStats(BaseModel):
    total_findings: int
    open_findings: int
    critical_findings: int
    alerts_active: int
    running_scans: int
    risk_score: int

@router.get("/api/v1/dashboard", response_model=DashboardStats)
async def get_dashboard():
    total = len(findings_db)
    open_cnt = sum(1 for f in findings_db.values() if f["status"] == "open")
    critical_cnt = sum(1 for f in findings_db.values() if f["severity"] == "critical")
    active_alerts = sum(1 for a in alerts_db.values() if a["status"] == "active")
    active_scans = sum(1 for s in scans_db.values() if s["status"] == "Running")
    
    # Simple risk score calc
    risk = min(100, (critical_cnt * 10) + (open_cnt * 2))
    
    return DashboardStats(
        total_findings=total,
        open_findings=open_cnt,
        critical_findings=critical_cnt,
        alerts_active=active_alerts,
        running_scans=active_scans,
        risk_score=risk or 28
    )

# ---------- Findings ----------
@router.get("/api/v1/findings")
async def list_findings(severity: Optional[str] = None, status: Optional[str] = None):
    results = list(findings_db.values())
    if severity:
        results = [f for f in results if f["severity"].lower() == severity.lower()]
    if status:
        results = [f for f in results if f["status"].lower() == status.lower()]
    return sorted(results, key=lambda x: x["created_at"], reverse=True)

@router.patch("/api/v1/findings/{fid}")
async def update_finding(fid: str, payload: Dict[str, Any]):
    if fid not in findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    findings_db[fid].update(payload)
    return {"status": "success"}

# ---------- Scans (VAPT) ----------
async def run_simulated_scan(scan_id: str):
    phases = ["Reconnaissance", "Enumeration", "Vulnerability Discovery", "Exploitation", "Reporting"]
    for i, phase in enumerate(phases):
        if scan_id not in scans_db: break
        scans_db[scan_id]["phase"] = phase
        scans_db[scan_id]["progress"] = int((i / len(phases)) * 100)
        await asyncio.sleep(2)
    if scan_id in scans_db:
        scans_db[scan_id]["progress"] = 100
        scans_db[scan_id]["status"] = "Completed"
        scans_db[scan_id]["phase"] = "Finished"

@router.post("/api/v1/scan")
async def start_scan(payload: Dict[str, Any], background_tasks: BackgroundTasks):
    sid = str(uuid.uuid4())[:8]
    scans_db[sid] = {
        "id": sid,
        "target": payload.get("target", "unknown"),
        "status": "Running",
        "progress": 0,
        "phase": "Initializing",
        "created_at": time.time()
    }
    background_tasks.add_task(run_simulated_scan, sid)
    return {"scan_id": sid}

@router.get("/api/v1/scan/{sid}")
async def get_scan_status(sid: str):
    if sid not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans_db[sid]

# ---------- Tasks (Red Team) ----------
@router.post("/api/v1/task")
async def create_task(payload: Dict[str, Any]):
    tid = str(uuid.uuid4())[:8]
    tasks_db[tid] = {
        "id": tid,
        "command": payload.get("command"),
        "status": "Running",
        "logs": [f"[*] Executing: {payload.get('command')}", "[+] Connection established", "[*] Analyzing target..."],
        "created_at": time.time()
    }
    return {"task_id": tid}

@router.get("/api/v1/task/{tid}/logs")
async def get_task_logs(tid: str, offset: int = 0):
    if tid not in tasks_db:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = tasks_db[tid]
    # Simulate adding more logs if it's still running
    if task["status"] == "Running" and len(task["logs"]) < 6:
        task["logs"].append(f"[+] Found vulnerability at {time.time()}")
        if len(task["logs"]) == 6:
            task["status"] = "Completed"
            task["logs"].append("[!] Task finished successfully.")
            
    return {
        "logs": task["logs"][offset:],
        "next_offset": len(task["logs"]),
        "status": task["status"]
    }

# ---------- Chat (LLM) ----------
@router.post("/api/v1/chat")
async def chat_with_ai(payload: Dict[str, Any]):
    msg = payload.get("message", "").lower()
    
    # Simulate intelligent response
    if "finding" in msg or "vulnerability" in msg:
        response = f"I've analyzed the current findings. There are {sum(1 for f in findings_db.values() if f['status'] == 'open')} open issues, including a critical Log4j vulnerability on web-prod-01."
        actions = [{"label": "View Critical Findings", "action": "nav:findings"}]
    elif "scan" in msg or "vapt" in msg:
        response = "I can initiate a new VAPT scan for you. Which target should I prioritize?"
        actions = [{"label": "Open VAPT Module", "action": "nav:vapt"}]
    elif "status" in msg or "dashboard" in msg:
        response = "System status is green. Risk score is currently 28. No major breaches detected in the last 24 hours."
        actions = [{"label": "Go to Dashboard", "action": "nav:dashboard"}]
    else:
        response = "I am the MAESTER Orchestrator. I can help you manage findings, run scans, or investigate alerts. How can I assist you today?"
        actions = []
        
    return {"response": response, "actions": actions}

# ---------- Alerts & Playbooks ----------
@router.get("/api/v1/alerts")
async def list_alerts():
    return list(alerts_db.values())

@router.post("/api/v1/playbook/{aid}/execute")
async def execute_playbook(aid: str):
    if aid not in alerts_db:
        raise HTTPException(status_code=404, detail="Alert not found")
    alerts_db[aid]["status"] = "resolved"
    return {"status": "success", "message": "Playbook executed and host isolated."}

# ---------- Reports ----------
@router.get("/api/v1/reports")
async def list_reports():
    return list(reports_db.values())

@router.post("/api/v1/reports/generate")
async def generate_report():
    rid = str(uuid.uuid4())[:8]
    reports_db[rid] = {
        "id": rid,
        "name": f"Security_Audit_{rid}.pdf",
        "created_at": time.time(),
        "status": "Completed"
    }
    return reports_db[rid]

# ---------- Threat Intel ----------
@router.get("/api/v1/threat-intel")
async def get_threat_intel():
    return threat_intel_db

# ---------- Notifications ----------
@router.get("/api/v1/notifications")
async def get_notifications():
    return notifications_db

@router.post("/api/v1/notifications/read")
async def mark_read():
    for n in notifications_db:
        n["read"] = True
    return {"status": "success"}

# ---------- Search ----------
@router.get("/api/v1/search")
async def search(q: str):
    q = q.lower()
    results = []
    for f in findings_db.values():
        if q in f["title"].lower() or q in f["asset"].lower():
            results.append({"type": "finding", "title": f["title"], "id": f["id"]})
    return results

# ---------- Compliance ----------
@router.get("/api/v1/compliance")
async def get_compliance():
    return [
        {"framework": "nist_csf", "compliant": 14, "non_compliant": 2, "not_tested": 4},
        {"framework": "iso_27001", "compliant": 18, "non_compliant": 5, "not_tested": 2},
        {"framework": "pci_dss", "compliant": 10, "non_compliant": 1, "not_tested": 9},
    ]

# ---------- Purple Team ----------
@router.get("/api/v1/purple-team")
async def get_purple_team():
    return {
        "attack_vectors": 14,
        "detection_coverage": 98.2,
        "mitre_matrix": [
            {"tactic": "Initial Access", "status": "monitored"},
            {"tactic": "Execution", "status": "blocked"},
            {"tactic": "Persistence", "status": "monitored"},
            {"tactic": "Privilege Escalation", "status": "blocked"},
            {"tactic": "Defense Evasion", "status": "monitored"},
        ]
    }

# ---------- Metrics ----------
from prometheus_client import generate_latest
@router.get("/metrics")
async def metrics():
    return generate_latest()
