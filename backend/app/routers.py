from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import uuid
import time

router = APIRouter()

# In‑memory demo data stores
findings_db: Dict[str, Dict[str, Any]] = {}
alerts_db: Dict[str, Dict[str, Any]] = {}
reports_db: Dict[str, Dict[str, Any]] = {}
notifications_db: List[Dict[str, Any]] = []
threat_intel_db: List[Dict[str, Any]] = []

# Helper to generate demo items
def _demo_finding() -> Dict[str, Any]:
    fid = str(uuid.uuid4())
    return {
        "id": fid,
        "title": f"Demo Finding {fid[:8]}",
        "severity": "high",
        "status": "open",
        "description": "Sample vulnerability discovered",
        "created_at": time.time(),
        "updated_at": time.time(),
    }

# Populate some demo data on import
for _ in range(5):
    f = _demo_finding()
    findings_db[f["id"]] = f

# ---------- Dashboard ----------
class DashboardStats(BaseModel):
    total_findings: int
    open_findings: int
    high_severity: int
    alerts_active: int
    running_scans: int

@router.get("/api/v1/dashboard", response_model=DashboardStats)
async def get_dashboard():
    total = len(findings_db)
    open_cnt = sum(1 for f in findings_db.values() if f["status"] == "open")
    high_cnt = sum(1 for f in findings_db.values() if f["severity"] == "high")
    alerts_active = len([a for a in alerts_db.values() if a.get("status") == "active"])
    running_scans = len([s for s in globals().get("scans_db", {}).values() if s.get("status") == "Running"])
    return DashboardStats(
        total_findings=total,
        open_findings=open_cnt,
        high_severity=high_cnt,
        alerts_active=alerts_active,
        running_scans=running_scans,
    )

# ---------- Findings ----------
class FindingOut(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    description: str
    created_at: float
    updated_at: float

@router.get("/api/v1/findings", response_model=List[FindingOut])
async def list_findings(severity: Optional[str] = None, status: Optional[str] = None):
    results = list(findings_db.values())
    if severity:
        results = [f for f in results if f["severity"] == severity]
    if status:
        results = [f for f in results if f["status"] == status]
    return results

@router.patch("/api/v1/findings/{fid}")
async def update_finding(fid: str, payload: Dict[str, Any]):
    if fid not in findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    findings_db[fid].update(payload)
    findings_db[fid]["updated_at"] = time.time()
    return {"status": "updated"}

@router.get("/api/v1/findings/export")
async def export_findings():
    # Very simple CSV string
    header = "id,title,severity,status,description,created_at,updated_at\n"
    rows = []
    for f in findings_db.values():
        rows.append(
            f"{f['id']},{f['title']},{f['severity']},{f['status']},{f['description']},{f['created_at']},{f['updated_at']}"
        )
    csv_content = header + "\n".join(rows)
    return {
        "filename": "findings_export.csv",
        "content": csv_content,
    }

# ---------- Alerts ----------
class AlertOut(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    created_at: float

@router.get("/api/v1/alerts", response_model=List[AlertOut])
async def list_alerts():
    return list(alerts_db.values())

@router.patch("/api/v1/alerts/{aid}")
async def update_alert(aid: str, payload: Dict[str, Any]):
    if aid not in alerts_db:
        raise HTTPException(status_code=404, detail="Alert not found")
    alerts_db[aid].update(payload)
    return {"status": "updated"}

# ---------- Compliance ----------
class ComplianceOut(BaseModel):
    framework: str
    compliant: int
    non_compliant: int
    not_tested: int

@router.get("/api/v1/compliance", response_model=List[ComplianceOut])
async def get_compliance():
    # Dummy static numbers for each framework
    frameworks = ["nist_csf", "nist_800_53", "iso_27001", "pci_dss", "hipaa", "soc_2", "cis_controls"]
    result = []
    for fw in frameworks:
        result.append(
            ComplianceOut(
                framework=fw,
                compliant=12,
                non_compliant=3,
                not_tested=5,
            )
        )
    return result

# ---------- Reports ----------
class ReportOut(BaseModel):
    id: str
    name: str
    created_at: float
    status: str

@router.post("/api/v1/reports/generate")
async def generate_report():
    rid = str(uuid.uuid4())
    reports_db[rid] = {
        "id": rid,
        "name": f"Audit_Report_{rid[:8]}.pdf",
        "created_at": time.time(),
        "status": "ready",
    }
    return {"report_id": rid, "status": "ready"}

@router.get("/api/v1/reports", response_model=List[ReportOut])
async def list_reports():
    return list(reports_db.values())

@router.get("/api/v1/reports/{rid}/download")
async def download_report(rid: str):
    if rid not in reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
    # In a real app, would stream the file. Here we return a placeholder URL.
    return {"download_url": f"/static/reports/{reports_db[rid]['name']}"}

# ---------- Threat Intel ----------
class IOC(BaseModel):
    id: str
    ioc_type: str
    value: str
    description: Optional[str]
    severity: Optional[str]

@router.get("/api/v1/threat-intel", response_model=List[IOC])
async def get_iocs():
    # Return a few static IOCs for demo
    return [
        IOC(id="1", ioc_type="ip", value="192.0.2.45", description="Known C2 server", severity="high"),
        IOC(id="2", ioc_type="domain", value="malicious.example.com", description="Phishing site", severity="medium"),
    ]

# ---------- Notifications ----------
class Notification(BaseModel):
    id: str
    message: str
    read: bool
    timestamp: float

@router.get("/api/v1/notifications", response_model=List[Notification])
async def get_notifications():
    return notifications_db

@router.post("/api/v1/notifications/read")
async def mark_notifications_read(ids: List[str]):
    for nid in ids:
        for n in notifications_db:
            if n["id"] == nid:
                n["read"] = True
    return {"status": "updated"}

# ---------- Search ----------
@router.get("/api/v1/search")
async def global_search(q: str):
    # Very naive search across demo stores
    results: Dict[str, List[Any]] = {"findings": [], "alerts": [], "reports": []}
    for f in findings_db.values():
        if q.lower() in f["title"].lower() or q.lower() in f["description"].lower():
            results["findings"].append(f)
    for a in alerts_db.values():
        if q.lower() in a.get("title", "").lower():
            results["alerts"].append(a)
    for r in reports_db.values():
        if q.lower() in r.get("name", "").lower():
            results["reports"].append(r)
    return results

# ---------- Metrics (Prometheus) ----------
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

REQUEST_COUNTER = Counter("maester_requests_total", "Total number of API requests", ["endpoint"])

@router.get("/metrics")
async def prometheus_metrics():
    # Increment a generic counter for demo purposes
    REQUEST_COUNTER.labels(endpoint="/metrics").inc()
    return generate_latest()
