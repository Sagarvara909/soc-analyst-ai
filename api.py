"""
api.py — FastAPI Backend for AI SOC Analyst (Week 2)
Run: uvicorn api:app --reload --port 8000
Docs: http://localhost:8000/docs
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import asyncio
import os
from datetime import datetime

from db import (
    init_db,
    get_recent_events,
    get_events_by_severity,
    get_anomalies,
    mark_false_positive,
    get_metrics,
    get_top_ips,
)

app = FastAPI(
    title="AI SOC Analyst API",
    description="Cybersecurity threat detection — ML ensemble + MITRE ATT&CK classifier",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()
    print("[API] Database ready")
    print("[API] Docs at http://localhost:8000/docs")


class FalsePositiveRequest(BaseModel):
    event_id: int
    reason:   Optional[str] = ""

class AnalyzeRequest(BaseModel):
    message:       str
    severity:      Optional[str]   = "UNKNOWN"
    source_ip:     Optional[str]   = "unknown"
    anomaly_score: Optional[float] = 0.0
    technique_id:  Optional[str]   = None
    tactic:        Optional[str]   = None


class ConnectionManager:
    def __init__(self): self.active = []
    async def connect(self, ws):
        await ws.accept(); self.active.append(ws)
    def disconnect(self, ws):
        if ws in self.active: self.active.remove(ws)

manager = ConnectionManager()


@app.get("/")
def root():
    return {
        "status":  "running",
        "service": "AI SOC Analyst API",
        "version": "2.0.0",
        "docs":    "http://localhost:8000/docs",
        "time":    datetime.now().isoformat(),
    }


@app.get("/metrics")
def metrics():
    try:
        m = get_metrics(); ips = get_top_ips(limit=5)
        return {**m, "top_ips": ips}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/events")
def events(limit: int = 50):
    try:
        data = get_recent_events(limit=limit)
        return {"events": data, "count": len(data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/events/anomalies")
def anomaly_events(limit: int = 50):
    try:
        data = get_anomalies(limit=limit)
        return {"events": data, "count": len(data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/events/severity/{severity}")
def events_by_severity(severity: str, limit: int = 50):
    if severity.upper() not in {"CRITICAL","HIGH","MEDIUM","LOW","INFO"}:
        raise HTTPException(400, "Severity must be: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    try:
        data = get_events_by_severity(severity.upper(), limit=limit)
        return {"events": data, "count": len(data), "severity": severity.upper()}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/events/mark-fp")
def mark_fp(req: FalsePositiveRequest):
    try:
        ok = mark_false_positive(req.event_id, reason=req.reason)
        if not ok:
            raise HTTPException(404, f"Event {req.event_id} not found")
        return {"success": True, "event_id": req.event_id, "message": f"Event {req.event_id} marked as false positive"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/analyze")
def analyze_threat(req: AnalyzeRequest):
    msg = req.message.lower(); score = req.anomaly_score or 0.0

    if "sql" in msg or "inject" in msg or "union" in msg:
        analysis = "[SQL Injection — T1190] Attacker injecting SQL payloads to bypass authentication or extract database contents. Immediate WAF rule update required."
        recs = ["Block source IP at WAF", "Audit all DB query logs", "Check for data exfiltration"]
    elif "failed password" in msg or "invalid user" in msg or "4625" in msg:
        analysis = f"[Brute Force — T1110.001] Automated credential stuffing from {req.source_ip}. High failure rate confirms scripted attack tool in use."
        recs = ["Block IP at firewall", "Enable account lockout after 5 attempts", "Enforce MFA on all external services"]
    elif "powershell" in msg or "encoded" in msg or "-enc" in msg:
        analysis = "[Encoded PowerShell — T1059.001] Base64-encoded PowerShell detected. Common malware dropper technique to bypass AV signatures."
        recs = ["Decode and inspect the payload immediately", "Isolate the affected host", "Review PowerShell execution policy"]
    elif "lsass" in msg or "credential dump" in msg or "mimikatz" in msg:
        analysis = "[Credential Dumping — T1055.012] LSASS memory read detected. Attacker extracting plaintext passwords and NTLM hashes from memory."
        recs = ["Isolate host IMMEDIATELY", "Reset ALL domain credentials", "Enable Windows Credential Guard"]
    elif "185.220" in msg or "beacon" in msg or "c2" in msg:
        analysis = "[C2 Beacon — T1071.001] Host communicating with known C2 infrastructure. Active malware infection confirmed."
        recs = ["Isolate host from network NOW", "Capture memory image for forensics", "Hunt this IOC across all hosts"]
    elif "1102" in msg or "audit log" in msg:
        analysis = "[Log Tampering — T1562.001] Windows audit log cleared. Strong indicator of hands-on attacker covering tracks."
        recs = ["Treat system as fully compromised", "Check offsite SIEM log copies", "Initiate incident response immediately"]
    elif float(score) >= 0.7:
        analysis = f"[High Anomaly — Score {score:.2f}/1.0] Event significantly outside normal baseline. Manual investigation required."
        recs = ["Review full IP activity history", "Cross-reference with threat intelligence", "Check time-correlated events"]
    else:
        analysis = f"[Low Risk — Score {score:.2f}/1.0] Activity within normal baseline. No immediate action required."
        recs = ["Continue monitoring", "No immediate action needed"]

    return {
        "analysis": analysis, "recommendations": recs,
        "technique_id": req.technique_id, "severity": req.severity,
        "anomaly_score": req.anomaly_score,
        "source": "rule-based (Claude AI added in Week 3)",
        "event_message": req.message,
    }


@app.get("/correlations/graph")
def correlation_graph(limit: int = 50):
    try:
        events = get_recent_events(limit=limit)
        nodes = [{"id": e["id"], "label": e["source_ip"], "score": e["anomaly_score"], "severity": e["severity"], "technique": e.get("technique_id","")} for e in events]
        ip_map = {}
        for n in nodes: ip_map.setdefault(n["label"], []).append(n["id"])
        edges = [{"source": ids[i], "target": ids[i+1], "relation": "same_ip"} for ids in ip_map.values() for i in range(len(ids)-1)]
        return {"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges)}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            try:
                recent = get_recent_events(limit=5)
                if recent:
                    await websocket.send_json({"type": "events", "events": recent[:3], "time": datetime.now().isoformat()})
            except Exception:
                pass
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        manager.disconnect(websocket)