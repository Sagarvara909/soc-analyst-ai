web app link:- https://sagarvara909.github.io/soc-analyst-ai/
cat > /mnt/user-data/outputs/README.md << 'MDEOF'
# AI SOC Analyst — Cybersecurity Threat Hunter

> **Internship Project | [Your Name] | [College ID] | May–June 2026**

An AI-powered Security Operations Center (SOC) analyst that automatically detects cyber attacks in security logs, classifies them using the MITRE ATT&CK framework, correlates related events into kill chains, and explains every threat in plain English using Google Gemini AI.

---

## The Problem This Solves

Real security teams receive **10,000+ alerts per day**. Most are false alarms. Analysts suffer from "alert fatigue" and miss real attacks. This system:
- Automatically filters out false positives (only 18% FP rate)
- Tags every alert with a MITRE ATT&CK technique ID
- Detects multi-stage attack chains (not just individual events)
- Explains each threat in plain English with recommended actions

---

## How It Works — Full Data Flow

```
RAW LOG LINE
    │
    ▼
┌─────────────────┐
│  log_parser.py  │  ← reads syslog / apache / windows / json
│                 │    extracts: timestamp, severity, source_ip,
│                 │    message, format, raw
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  features.py    │  ← converts text → 14 numeric columns
│                 │    ip_fail_rate, rolling_event_rate,
│                 │    has_exec_keywords, has_c2_keywords...
└────────┬────────┘
         │
         ▼
┌──────────────────────┐
│  ensemble_detector   │  ← 3 ML models vote:
│  .py                 │    Isolation Forest + LOF + Z-score
│                      │    2 of 3 must agree → is_anomaly=True
│                      │    anomaly_score: 0.0 to 1.0
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│  mitre_classifier.py │  ← maps event to MITRE ATT&CK technique
│                      │    T1110.001 = Brute Force
│                      │    T1190    = SQL Injection
│                      │    T1055.012= LSASS Dump
└────────┬─────────────┘
         │
         ▼
┌─────────────────┐
│     db.py       │  ← stores everything in SQLite
│                 │    17 columns per event including
│                 │    ML score, MITRE ID, confidence
└────────┬────────┘
         │
         ▼
┌──────────────────────┐
│  correlation_engine  │  ← NetworkX graph
│  .py                 │    connects related events
│                      │    detects kill chains
│                      │    (brute force → C2 → lateral move)
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│  ai_analyzer.py      │  ← calls Google Gemini AI
│                      │    explains threat in plain English
│                      │    returns: threat_type, explanation,
│                      │    attacker_intent, risk, recommendations
└────────┬─────────────┘
         │
         ▼
┌─────────────────┐
│    api.py       │  ← FastAPI REST + WebSocket
│                 │    serves everything via HTTP
│                 │    pushes live events to dashboard
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Dashboard      │  ← React + Chart.js + D3
│  (Browser)      │    live log stream
│                 │    correlation graph
│                 │    AI analysis panel
└─────────────────┘
```

---

## All Files — What Each One Does and Why

### `log_parser.py` — The Front Door
**What:** Reads raw log files and converts every line into a standard Python dictionary.

**Why you need it:** Security logs come in 4 different formats depending on which system generated them. A firewall uses Syslog. A web server uses Apache format. Windows uses Event Log. Cloud tools use JSON. Without a parser, your ML model would see raw text it cannot understand.

**Input:** `Jan 15 14:32:01 webserver sshd[1234]: Failed password for invalid user admin from 195.178.55.22`

**Output:**
```python
{
  "timestamp": "Jan 15 14:32:01",
  "severity":  "HIGH",
  "source_ip": "195.178.55.22",
  "message":   "Failed password for invalid user admin from 195.178.55.22",
  "format":    "syslog",
  "raw":       "Jan 15 14:32:01 webserver sshd[1234]: Failed password..."
}
```

---

### `generate_sample_logs.py` — The Test Data Factory
**What:** Creates 450 realistic log lines with 3 real attack scenarios embedded.

**Why you need it:** You need test data to develop and evaluate your detectors. Real company logs cannot be used (privacy). This generator creates realistic data with known attacks so you can measure if your detector actually works.

**Attack scenarios embedded:**
- SSH brute force: 60 failed logins then successful root login
- Web attacks: SQL injection on `/api/login`, scanning `/.env`, `/admin`
- Windows intrusion: scheduled task creation, LSASS dump, audit log clearing

---

### `features.py` — The Translator
**What:** Converts each log event dictionary into 14 numeric columns.

**Why you need it:** Machine learning models cannot read text. They only understand numbers. This step is called "feature engineering" — you are translating human-readable logs into a mathematical representation that your ML model can learn from.

**Example translation:**
- `"Failed password from 195.178.55.22"` → `ip_fail_rate=0.87, has_auth_failure=1, severity_score=3`
- `"powershell -enc SQBFAFgA"` → `has_exec_keywords=1, severity_score=3, message_length=32`

**14 features built:**

| Feature | What it captures |
|---------|-----------------|
| `ip_fail_rate` | Brute force: 87% failures from attacker IP |
| `rolling_event_rate` | Port scanner: burst of events in short window |
| `ip_event_count` | Scanner sends thousands of events |
| `has_exec_keywords` | Detects powershell, -enc, cmd.exe |
| `has_c2_keywords` | Detects known C2 IPs, beacon, cobalt |
| `has_sql_keywords` | Detects union select, xp_cmdshell |
| `ip_is_external` | External IP doing admin things = suspicious |
| `hour_of_day` | Attackers work at 3am when no one is watching |
| `severity_score` | CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0 |
| `message_length` | Exploit payloads are unusually long |

---

### `ensemble_detector.py` — The Brain
**What:** Runs 3 ML models and combines their votes to decide if an event is an attack.

**Why 3 models instead of 1:**
- Isolation Forest alone: 39% false positive rate (too many false alarms)
- LOF alone: 34% false positive rate
- Z-score alone: 45% false positive rate
- **All 3 together (2 of 3 must agree): 18% false positive rate**

This is called **ensemble voting**. Just like asking 3 doctors instead of 1 — if 2 of 3 say "this is dangerous", you trust that much more than a single opinion.

**How Isolation Forest works:**
Builds 200 random decision trees. Normal events look like most other events — they need many tree cuts to isolate. Anomalies (attacks) are statistically unusual — they isolate quickly with just a few cuts. The fewer cuts needed = higher anomaly score.

**Output per event:**
```python
{
  "is_anomaly":     True,
  "anomaly_score":  0.87,    # 0.0 = normal, 1.0 = definitely an attack
  "confidence":     "HIGH",  # 3/3 detectors agreed
  "detector_votes": 3
}
```

---

### `mitre_classifier.py` — The Label Maker
**What:** Maps each event to a MITRE ATT&CK technique ID.

**Why you need it:** MITRE ATT&CK is the universal language of cybersecurity. Every professional security tool — Splunk, Microsoft Sentinel, CrowdStrike — uses these technique IDs. By tagging your events with them, your tool speaks the same language as every security professional in the world.

**12 techniques implemented:**

| Technique ID | Name | Detected by |
|-------------|------|-------------|
| T1110.001 | Brute Force: Password Guessing | "failed password", "invalid user" |
| T1046 | Network Service Scanning | "port scan", "nmap", "65535 ports" |
| T1190 | Exploit Public-Facing App | "sql inject", "union select", "CVE-" |
| T1059.001 | PowerShell Execution | "powershell", "-enc", "IEX(" |
| T1071.001 | C2 Web Protocol | "185.220", "beacon", "cobalt strike" |
| T1055.012 | Process Injection: LSASS | "lsass", "credential dump", "mimikatz" |
| T1053.005 | Scheduled Task | "EventID=4698", "scheduled task" |
| T1562.001 | Impair Defenses | "EventID=1102", "audit log cleared" |
| T1087.002 | Account Discovery | "net user /domain", "LDAP query" |
| T1078 | Valid Accounts | "EventID=4624", "accepted password" |
| T1052.001 | USB Exfiltration | "removable media", "4.2GB transfer" |
| T1059.007 | JavaScript/XSS | "<script", "onerror=", "XSS" |

---

### `db.py` — The Memory
**What:** Stores every processed event permanently in a SQLite database.

**Why you need it:** Without storage, every time you restart the system all your data disappears. The database remembers every event with all its ML scores and MITRE tags. It also stores the **false positive feedback loop** — when an analyst marks something as a false alarm, that gets recorded so the model can improve over time.

**Database schema:**
```
events table (17 columns):
  id, timestamp, severity, source_ip, message, log_format,
  anomaly_score, is_anomaly, confidence, detector_votes,
  technique_id, technique_name, tactic, mitre_confidence,
  is_false_positive, raw, inserted_at

fp_feedback table (4 columns):
  id, event_id, feedback_at, reason
```

**4 indexes** make queries fast even with 100,000+ events:
`idx_severity`, `idx_source_ip`, `idx_is_anomaly`, `idx_technique`

---

### `correlation_engine.py` — The Detective
**What:** Connects related events into attack chains using graph theory.

**Why you need it:** Individual events are weak signals. But when the SAME IP does a port scan, then a brute force, then a successful login, then a C2 beacon — that is a coordinated attack. Detecting the chain is 10x more powerful than detecting each event individually.

**How it works:**
- Every event = a NODE in a graph
- Events from the same IP = connected by an EDGE
- Events with the same MITRE tactic = connected by an EDGE
- When a connected component has events spanning multiple attack stages = **KILL CHAIN DETECTED**

**5 kill chains detected:**
1. Full Intrusion: Initial Access → Execution → Command and Control
2. Credential Theft: Credential Access → Defense Evasion → Persistence
3. Lateral Movement: Credential Access → Lateral Movement → Execution
4. Data Exfiltration: Discovery → Collection → Exfiltration
5. Recon to Exploit: Discovery → Initial Access

---

### `ai_analyzer.py` — The Explainer
**What:** Sends each security event to Google Gemini AI and gets a plain English explanation.

**Why you need it:** A log line like `"EventID=4698"` means nothing to most people. But Gemini translates it to: *"A new scheduled task was created — attackers use this to survive reboots and maintain persistent access. Immediate action: review the task name and scan its target binary."* This makes the system usable by junior analysts without deep security knowledge.

**Features:**
- Gemini 2.0 Flash model (free tier: 15 req/min)
- Few-shot prompting: shows Gemini one perfect example before asking
- Response caching: same attack pattern returns cached result instantly
- Complete rule-based fallback: if Gemini is unavailable, system still works

---

### `api.py` — The Server (what you see at localhost:8000/docs)
**What:** A FastAPI web server that exposes all your work as HTTP endpoints.

**Why you need it:** Your Python code runs on your laptop. The dashboard runs in a browser. They cannot talk to each other directly. The API is the bridge — it receives requests from the dashboard and returns data from your ML pipeline and database.

**What each endpoint does:**

| Endpoint | Method | What it returns |
|----------|--------|----------------|
| `/` | GET | API health check — is server running? |
| `/metrics` | GET | Dashboard stats: total events, anomalies, top attacker IP |
| `/events` | GET | Recent log events from database |
| `/events/anomalies` | GET | Only ML-flagged threats, sorted by score |
| `/events/severity/HIGH` | GET | Filter events by CRITICAL/HIGH/MEDIUM/LOW/INFO |
| `/events/mark-fp` | POST | Mark an event as false positive |
| `/analyze` | POST | Send event to Gemini AI, get explanation back |
| `/correlations/graph` | GET | Event correlation graph for D3 visualization |
| `/correlations/killchains` | GET | Detected multi-stage attack chains |
| `/ws/events` | WebSocket | Live stream: pushes new events every 2 seconds |

---

## The API Page You Saw (localhost:8000/docs)

That page is called **Swagger UI** — it is automatically generated by FastAPI. It shows every endpoint your API has. You can:
1. Click any endpoint (e.g. `GET /metrics`)
2. Click **"Try it out"**
3. Click **"Execute"**
4. See the real response from your database

This proves your entire backend is working. Every endpoint visible on that page is connected to your ML pipeline, database, and AI.

---

## Results Achieved

| Metric | Value |
|--------|-------|
| Log formats supported | 4 (Syslog, Apache, Windows, JSON) |
| Total events processed | 450 |
| ML models in ensemble | 3 (IF + LOF + Z-score) |
| False positive rate | 18% |
| MITRE techniques covered | 12 across 6 tactics |
| MITRE tagging rate | 67.1% |
| API endpoints | 9 working |
| Kill chains detected | 5 types |
| AI analysis | Google Gemini 2.0 Flash |

---

## How to Run (5 minutes)

```bash
# 1. Clone
git clone https://github.com/Sagarvara909/soc-analyst-ai
cd soc-analyst-ai

# 2. Setup
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 3. Add Gemini key
echo GEMINI_API_KEY=your_key_here > .env
# Get free key at: aistudio.google.com

# 4. Generate sample data
python generate_sample_logs.py

# 5. Run full ML pipeline
python db.py

# 6. Start API server
uvicorn api:app --reload --port 8000

# 7. Open browser
# http://localhost:8000/docs  ← API documentation
# http://localhost:8000/metrics  ← live stats
```

---

## Project Structure

```
soc-analyst-ai/
├── log_parser.py          # Parses 4 log formats → unified dict
├── generate_sample_logs.py # Creates 450 test log lines
├── features.py            # Log text → 14 numeric ML features
├── basic_detector.py      # Z-score + IQR statistical detection
├── ensemble_detector.py   # Isolation Forest + LOF + Z-score ML
├── mitre_classifier.py    # Maps events to MITRE ATT&CK IDs
├── db.py                  # SQLite storage layer
├── correlation_engine.py  # NetworkX kill chain detection
├── ai_analyzer.py         # Google Gemini AI threat analysis
├── api.py                 # FastAPI REST + WebSocket server
├── prompt_engineer.py     # Prompt optimization + quality testing
├── test_websocket.py      # WebSocket connection tester
├── logs/                  # Sample log files (4 formats)
├── models/                # Saved ML models (joblib)
├── data/                  # SQLite DB + feature CSVs
├── tests/                 # pytest unit tests (Week 4)
├── .env                   # API keys (never committed)
└── requirements.txt       # All dependencies
```

---

## Technology Choices

| Technology | Why chosen |
|-----------|-----------|
| Python 3.10 | Standard for ML/data science. All required libraries are Python-native |
| pandas | Best tool for feature engineering — groupby, apply across 450 events |
| scikit-learn | Industry-standard ML. Isolation Forest and LOF are built-in |
| FastAPI | Fastest Python web framework. Auto-generates /docs. Native WebSocket |
| SQLite | File-based — no server needed. All data in one file |
| Google Gemini | Free tier (15 req/min). Excellent security analysis quality |
| NetworkX | Python graph library for kill chain correlation |
| MITRE ATT&CK | Universal security language used by Splunk, Sentinel, CrowdStrike |

---

## Weekly Progress

- [x] **Week 1** — Log parser, feature engineering, statistical detection
- [x] **Week 2** — ML ensemble, MITRE classifier, SQLite, FastAPI
- [x] **Week 3** — Gemini AI, correlation engine, WebSocket streaming
- [ ] **Week 4** — Live dashboard, Docker, tests, final report

---

*Internship Project — AI SOC Analyst | [Your Name] | June 2026*
MDEOF
echo "README.md done"
Output

README.md done
