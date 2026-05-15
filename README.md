# AI SOC Analyst — Cybersecurity Threat Hunter

> Internship Project | [YOUR NAME] | May–June 2026

An AI-powered Security Operations Center (SOC) analyst that detects attacks, analyzes logs, correlates events, and explains threats using machine learning and the Claude AI API.

---

## What it does

- **Detects anomalies** in security logs using an ensemble of Isolation Forest, Local Outlier Factor, and Z-score methods
- **Classifies threats** by mapping events to MITRE ATT&CK technique IDs (T1110, T1046, T1190...)
- **Correlates events** using a graph engine (NetworkX) to detect kill chains: scan → exploit → C2 → lateral movement
- **Explains threats** in plain English using the Anthropic Claude API
- **Streams live** via WebSocket to a React dashboard with real-time anomaly scoring

---

## System Architecture

```
Log Sources (Firewall, IDS, EDR, DNS, VPN)
        ↓
log_parser.py       — parse syslog, Apache, Windows Event, JSON formats
        ↓
features.py         — extract numeric features into pandas DataFrame
        ↓
ensemble_detector.py — Isolation Forest + LOF + Z-score voting
        ↓
mitre_classifier.py  — map events to MITRE ATT&CK technique IDs
        ↓
SQLite database      — persist all events + anomaly scores
        ↓
correlation_engine.py — NetworkX graph, kill chain detection
        ↓
ai_analyzer.py       — Claude API threat explanation
        ↓
FastAPI + WebSocket   — REST API + real-time event streaming
        ↓
React Dashboard      — live log stream, correlation graph, AI analysis
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, FastAPI |
| ML / Detection | scikit-learn (Isolation Forest, LOF), pandas |
| Correlation | NetworkX |
| AI Analysis | Anthropic Claude API |
| Frontend | React, Chart.js, D3 |
| Storage | SQLite |
| Deployment | Docker, docker-compose |

---

## Weekly Progress

- [x] Week 1 — Log parsing + statistical anomaly detection
- [ ] Week 2 — ML detection engine (Isolation Forest ensemble)
- [ ] Week 3 — AI integration + event correlation
- [ ] Week 4 — Dashboard connection + Docker + delivery

---

## How to run (5 minutes)

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/soc-analyst-ai
cd soc-analyst-ai

# 2. Setup
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt

# 3. Add API key
echo ANTHROPIC_API_KEY=your_key_here > .env

# 4. Run backend
uvicorn api:app --reload

# 5. Open dashboard
# navigate to frontend/ and open index.html
```

---

## Project structure

```
soc-analyst-ai/
├── log_parser.py          # Log ingestion and parsing
├── features.py            # Feature engineering
├── basic_detector.py      # Statistical anomaly detection
├── ensemble_detector.py   # ML ensemble (Week 2)
├── mitre_classifier.py    # MITRE ATT&CK tagging (Week 2)
├── db.py                  # SQLite persistence (Week 2)
├── api.py                 # FastAPI backend (Week 2)
├── correlation_engine.py  # Graph-based correlation (Week 3)
├── ai_analyzer.py         # Claude API integration (Week 3)
├── logs/                  # Sample log files
├── models/                # Saved ML models
├── tests/                 # pytest test suite
└── frontend/              # React dashboard
```

---

*Internship project — AI Cybersecurity Threat Hunter*
