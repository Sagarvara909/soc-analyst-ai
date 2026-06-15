"""
api.py — AI SOC Analyst v4.0
==============================
FastAPI backend with:
  - 10 REST endpoints
  - 3 data source switcher endpoints (sample / real PC / combined)
  - WebSocket live streaming
  - Gemini AI threat analysis
  - NetworkX correlation graph
  - Real-time event broadcasting

Run: uvicorn api:app --reload --port 8000
Docs: http://localhost:8000/docs
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import asyncio, os
from datetime import datetime

from db import (
    init_db, get_recent_events, get_events_by_severity,
    get_anomalies, mark_false_positive, get_metrics, get_top_ips
)

app = FastAPI(
    title="AI SOC Analyst API",
    description="Cybersecurity threat detection — ML + MITRE + Gemini AI + Correlation",
    version="4.0.0",
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
    print("[API] v4.0 started — http://localhost:8000/docs")


# ── Request models ────────────────────────────────────────────────

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


# ── WebSocket Manager ─────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active      = []
        self.send_counts = {}
        self.MAX_PER_SEC = 50

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        self.send_counts[id(ws)] = 0
        print(f"[WS] Client connected → total: {len(self.active)}")
        try:
            m = get_metrics()
            await ws.send_json({
                "type":    "connected",
                "message": f"Connected to AI SOC Analyst — {m.get('total_events',0)} events in DB",
                "metrics": m,
                "time":    datetime.now().isoformat(),
            })
        except Exception:
            pass

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)
        self.send_counts.pop(id(ws), None)
        print(f"[WS] Client disconnected → total: {len(self.active)}")

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            count = self.send_counts.get(id(ws), 0)
            if count >= self.MAX_PER_SEC:
                continue
            try:
                await ws.send_json(data)
                self.send_counts[id(ws)] = count + 1
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def reset_counts(self):
        for k in self.send_counts:
            self.send_counts[k] = 0

    @property
    def connection_count(self):
        return len(self.active)


manager = ConnectionManager()

async def reset_rate_limits():
    while True:
        await asyncio.sleep(1)
        manager.reset_counts()


# ── Helper: run full pipeline ─────────────────────────────────────

def _run_pipeline(events, contamination=0.1):
    """Run full ML + MITRE pipeline and store in main DB."""
    from features import build_features
    from ensemble_detector import run_ensemble
    from mitre_classifier import classify_events

    df     = build_features(events)
    result = run_ensemble(df, contamination=contamination)
    clss   = classify_events(events)
    dets   = result[["anomaly_score","is_anomaly","confidence","detector_votes"]].to_dict(orient="records")

    DB = "data/soc_analyst.db"
    if os.path.exists(DB):
        os.remove(DB)
    init_db(db_path=DB)

    from db import insert_events_bulk
    count = insert_events_bulk(events, dets, clss, db_path=DB)
    return count


# ── REST Endpoints ────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "status":      "running",
        "service":     "AI SOC Analyst API",
        "version":     "4.0.0",
        "docs":        "http://localhost:8000/docs",
        "websocket":   "ws://localhost:8000/ws/events",
        "connections": manager.connection_count,
        "time":        datetime.now().isoformat(),
    }


@app.get("/metrics")
def metrics():
    try:
        m   = get_metrics()
        ips = get_top_ips(limit=5)
        return {**m, "top_ips": ips, "ws_connections": manager.connection_count}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/events")
def events(limit: int = 50):
    try:
        data = get_recent_events(limit=limit)
        return {"events": data, "count": len(data)}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/events/anomalies")
def anomaly_events(limit: int = 50):
    try:
        data = get_anomalies(limit=limit)
        return {"events": data, "count": len(data)}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/events/severity/{severity}")
def events_by_severity(severity: str, limit: int = 50):
    if severity.upper() not in {"CRITICAL","HIGH","MEDIUM","LOW","INFO"}:
        raise HTTPException(400, "Invalid severity level")
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
        return {"success": True, "event_id": req.event_id,
                "message": f"Event {req.event_id} marked as false positive"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/analyze")
async def analyze_event(req: AnalyzeRequest):
    try:
        from ai_analyzer import analyze_threat
        event = {
            "message":       req.message,
            "severity":      req.severity,
            "source_ip":     req.source_ip,
            "anomaly_score": req.anomaly_score,
            "technique_id":  req.technique_id,
            "tactic":        req.tactic,
        }
        result = analyze_threat(event)
        result["event_message"] = req.message
        if manager.connection_count > 0:
            await manager.broadcast({
                "type":   "analysis",
                "result": result,
                "event":  event,
                "time":   datetime.now().isoformat(),
            })
        return result
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/correlations/graph")
def correlation_graph(limit: int = 100):
    try:
        from correlation_engine import get_graph_json
        events = get_recent_events(limit=limit)
        return get_graph_json(events)
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/correlations/killchains")
def kill_chains(limit: int = 200):
    try:
        from correlation_engine import correlate_events
        events = get_recent_events(limit=limit)
        _, _, chains = correlate_events(events)
        return {"kill_chains": chains, "count": len(chains), "events_scanned": len(events)}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/ws/test")
async def ws_test():
    if manager.connection_count == 0:
        return {"message": "No WebSocket clients connected."}
    await manager.broadcast({
        "type":    "test",
        "message": "Test broadcast from server",
        "clients": manager.connection_count,
        "time":    datetime.now().isoformat(),
    })
    return {"message": f"Test sent to {manager.connection_count} client(s)"}


# ── DATA SOURCE SWITCHER ──────────────────────────────────────────

@app.post("/switch/sample")
def switch_to_sample():
    """Switch dashboard to show 450 sample attack logs."""
    try:
        from log_parser import parse_log_file
        all_events = []
        for path in ["logs/syslog_sample.log","logs/apache_access.log",
                     "logs/windows_events.log","logs/json_structured.log"]:
            if os.path.exists(path):
                evts = parse_log_file(path)
                all_events.extend(evts)

        if not all_events:
            raise HTTPException(400, "Sample log files not found. Run: python generate_sample_logs.py")

        count = _run_pipeline(all_events, contamination=0.1)
        m     = get_metrics()
        return {
            "success": True,
            "mode":    "sample",
            "message": f"Switched to sample logs — {count} events loaded",
            "metrics": m,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/switch/realpc")
def switch_to_realpc():
    """Switch dashboard to show real Windows PC logs."""
    try:
        from parse_windows_real import parse_wevtutil_file
        all_events = []
        for path in ["logs/real_windows_security.log",
                     "logs/real_windows_system.log",
                     "logs/real_windows_app.log"]:
            if os.path.exists(path):
                evts = parse_wevtutil_file(path)
                all_events.extend(evts)

        if not all_events:
            raise HTTPException(400,
                "Real PC log files not found. Run: wevtutil qe System /c:200 /f:text > logs\\real_windows_system.log")

        count = _run_pipeline(all_events, contamination=0.05)
        m     = get_metrics()
        return {
            "success": True,
            "mode":    "realpc",
            "message": f"Switched to real PC logs — {count} events loaded",
            "metrics": m,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/switch/combined")
def switch_to_combined():
    """Switch dashboard to show sample + real PC logs together."""
    try:
        from log_parser import parse_log_file
        all_events = []

        # Sample logs
        for path in ["logs/syslog_sample.log","logs/apache_access.log",
                     "logs/windows_events.log","logs/json_structured.log"]:
            if os.path.exists(path):
                all_events.extend(parse_log_file(path))

        # Real PC logs
        try:
            from parse_windows_real import parse_wevtutil_file
            for path in ["logs/real_windows_security.log","logs/real_windows_system.log"]:
                if os.path.exists(path):
                    all_events.extend(parse_wevtutil_file(path))
        except Exception:
            pass

        if not all_events:
            raise HTTPException(400, "No log files found.")

        count = _run_pipeline(all_events, contamination=0.05)
        m     = get_metrics()
        return {
            "success": True,
            "mode":    "combined",
            "message": f"Switched to combined — {count} events loaded",
            "metrics": m,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


# ── WebSocket ─────────────────────────────────────────────────────

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await manager.connect(websocket)
    asyncio.create_task(reset_rate_limits())
    last_event_id = 0
    tick = 0
    try:
        while True:
            try:
                recent = get_recent_events(limit=10)
                new_events = [e for e in recent if e.get("id", 0) > last_event_id]
                if new_events:
                    last_event_id = max(e.get("id", 0) for e in new_events)
                    await websocket.send_json({
                        "type":   "new_events",
                        "events": new_events,
                        "count":  len(new_events),
                        "time":   datetime.now().isoformat(),
                    })
                if tick % 10 == 0:
                    m = get_metrics()
                    await websocket.send_json({
                        "type":    "metrics",
                        "metrics": m,
                        "time":    datetime.now().isoformat(),
                    })
                if tick % 30 == 0:
                    try:
                        from correlation_engine import correlate_events
                        sample = get_recent_events(limit=100)
                        _, _, chains = correlate_events(sample)
                        if chains:
                            await websocket.send_json({
                                "type":        "kill_chains",
                                "kill_chains": chains,
                                "count":       len(chains),
                                "time":        datetime.now().isoformat(),
                            })
                    except Exception:
                        pass
            except Exception:
                pass
            tick += 1
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        manager.disconnect(websocket)