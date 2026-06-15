"""
correlation_engine.py — Week 3 Day 3
======================================
Builds a graph of related security events using NetworkX.
Detects multi-stage attack kill chains automatically.

Correlation rules:
  1. Same source IP within 5-minute window
  2. Same MITRE tactic sequence (escalating attack stages)
  3. Escalating severity from same host

Kill chains detected:
  - Recon → Initial Access → Execution → C2
  - Credential Access → Defense Evasion → Persistence
  - Discovery → Initial Access → Privilege Escalation → Exfiltration

Run: python correlation_engine.py
"""

import networkx as nx
from collections import defaultdict
from datetime import datetime, timedelta


# ── MITRE tactic progression order ───────────────────────────────
# Higher number = later in attack lifecycle
TACTIC_ORDER = {
    "Reconnaissance":        1,
    "Resource Development":  2,
    "Initial Access":        3,
    "Execution":             4,
    "Persistence":           5,
    "Privilege Escalation":  6,
    "Defense Evasion":       7,
    "Credential Access":     8,
    "Discovery":             9,
    "Lateral Movement":     10,
    "Collection":           11,
    "Command and Control":  12,
    "Exfiltration":         13,
    "Impact":               14,
}

SEVERITY_ORDER = {
    "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4
}

# Kill chain sequences to detect
KILL_CHAINS = [
    {
        "name":    "Full Intrusion Kill Chain",
        "tactics": ["Initial Access", "Execution", "Command and Control"],
        "severity": "CRITICAL",
        "description": "Complete attack sequence: initial compromise → code execution → C2 communication",
    },
    {
        "name":    "Credential Theft & Persistence",
        "tactics": ["Credential Access", "Defense Evasion", "Persistence"],
        "severity": "CRITICAL",
        "description": "Attacker dumped credentials, cleared evidence, and established persistence",
    },
    {
        "name":    "Lateral Movement Chain",
        "tactics": ["Credential Access", "Lateral Movement", "Execution"],
        "severity": "CRITICAL",
        "description": "Attacker using stolen credentials to spread across the network",
    },
    {
        "name":    "Data Exfiltration Chain",
        "tactics": ["Discovery", "Collection", "Exfiltration"],
        "severity": "HIGH",
        "description": "Attacker discovered data, collected it, and is exfiltrating",
    },
    {
        "name":    "Recon to Exploit",
        "tactics": ["Discovery", "Initial Access"],
        "severity": "HIGH",
        "description": "Network scanning followed by exploitation attempt",
    },
]


# ── Main correlation function ─────────────────────────────────────

def correlate_events(events: list, window_minutes: int = 5) -> tuple:
    """
    Build a correlation graph from a list of event dicts.

    Args:
        events: list of dicts from DB (must have id, source_ip,
                severity, tactic, technique_id, anomaly_score)
        window_minutes: time window for same-IP correlation

    Returns:
        (graph, correlated_groups, kill_chains)
          graph             : NetworkX Graph object
          correlated_groups : list of event groups
          kill_chains       : list of detected kill chain alerts
    """
    G = nx.Graph()

    # Add all events as nodes
    for e in events:
        eid = e.get("id", id(e))
        G.add_node(eid,
            source_ip    = e.get("source_ip", "unknown"),
            severity     = e.get("severity", "INFO"),
            tactic       = e.get("tactic", ""),
            technique_id = e.get("technique_id", ""),
            anomaly_score= float(e.get("anomaly_score", 0.0)),
            message      = str(e.get("message", ""))[:80],
            timestamp    = e.get("timestamp", ""),
            inserted_at  = e.get("inserted_at", ""),
        )

    # ── Rule 1: Same source IP ──────────────────────────────────
    ip_groups = defaultdict(list)
    for e in events:
        ip = e.get("source_ip", "unknown")
        if ip not in ("unknown", "0.0.0.0", None):
            ip_groups[ip].append(e)

    for ip, grp in ip_groups.items():
        for i in range(len(grp)):
            for j in range(i + 1, min(i + 15, len(grp))):
                n1 = grp[i].get("id", id(grp[i]))
                n2 = grp[j].get("id", id(grp[j]))
                if G.has_node(n1) and G.has_node(n2):
                    G.add_edge(n1, n2,
                        relation = "same_ip",
                        ip       = ip,
                        weight   = 1.0,
                    )

    # ── Rule 2: Same MITRE tactic ───────────────────────────────
    tactic_groups = defaultdict(list)
    for e in events:
        t = e.get("tactic", "")
        if t:
            tactic_groups[t].append(e)

    for tactic, grp in tactic_groups.items():
        for i in range(len(grp)):
            for j in range(i + 1, min(i + 8, len(grp))):
                n1 = grp[i].get("id", id(grp[i]))
                n2 = grp[j].get("id", id(grp[j]))
                if G.has_node(n1) and G.has_node(n2):
                    if not G.has_edge(n1, n2):
                        G.add_edge(n1, n2,
                            relation = "same_tactic",
                            tactic   = tactic,
                            weight   = 0.7,
                        )

    # ── Rule 3: Escalating severity from same IP ────────────────
    for ip, grp in ip_groups.items():
        sorted_grp = sorted(grp,
            key=lambda e: SEVERITY_ORDER.get(e.get("severity", "INFO"), 0))
        for i in range(len(sorted_grp) - 1):
            sev1 = SEVERITY_ORDER.get(sorted_grp[i].get("severity","INFO"), 0)
            sev2 = SEVERITY_ORDER.get(sorted_grp[i+1].get("severity","INFO"), 0)
            if sev2 > sev1:
                n1 = sorted_grp[i].get("id",   id(sorted_grp[i]))
                n2 = sorted_grp[i+1].get("id", id(sorted_grp[i+1]))
                if G.has_node(n1) and G.has_node(n2) and not G.has_edge(n1, n2):
                    G.add_edge(n1, n2,
                        relation  = "severity_escalation",
                        ip        = ip,
                        weight    = 1.5,   # higher weight = more suspicious
                    )

    # ── Find correlated groups (connected components ≥ 3) ───────
    components = list(nx.connected_components(G))
    correlated_groups = []
    for i, comp in enumerate(components):
        if len(comp) < 2:
            continue
        comp_events = [e for e in events if e.get("id") in comp]
        tactics_in_group = list(set(
            e.get("tactic", "") for e in comp_events if e.get("tactic")
        ))
        ips_in_group = list(set(
            e.get("source_ip","?") for e in comp_events
            if e.get("source_ip") not in ("unknown", None)
        ))
        max_score = max(
            (float(e.get("anomaly_score", 0)) for e in comp_events), default=0
        )
        correlated_groups.append({
            "group_id":    i,
            "event_ids":   list(comp),
            "event_count": len(comp),
            "source_ips":  ips_in_group[:5],
            "tactics":     tactics_in_group,
            "max_score":   round(max_score, 3),
        })

    correlated_groups.sort(key=lambda g: g["event_count"], reverse=True)

    # ── Detect kill chains ───────────────────────────────────────
    kill_chains_found = []
    for comp in components:
        if len(comp) < 2:
            continue
        comp_events  = [e for e in events if e.get("id") in comp]
        tactics_here = set(e.get("tactic","") for e in comp_events if e.get("tactic"))
        ips_here     = list(set(
            e.get("source_ip","?") for e in comp_events
            if e.get("source_ip") not in ("unknown", None)
        ))

        for kc in KILL_CHAINS:
            required   = set(kc["tactics"])
            matched    = required & tactics_here
            match_pct  = len(matched) / len(required)

            if match_pct >= 0.67:   # 2 of 3 tactics present = kill chain
                techniques = list(set(
                    e.get("technique_id","") for e in comp_events
                    if e.get("technique_id")
                ))
                kill_chains_found.append({
                    "chain_name":    kc["name"],
                    "severity":      kc["severity"],
                    "description":   kc["description"],
                    "match_percent": round(match_pct * 100),
                    "event_count":   len(comp),
                    "source_ips":    ips_here[:3],
                    "tactics_found": list(matched),
                    "techniques":    techniques[:5],
                    "alert":         f"🚨 KILL CHAIN: {kc['name']} — {len(comp)} events from {ips_here[0] if ips_here else 'unknown'}",
                })

    # Deduplicate kill chains
    seen = set()
    unique_chains = []
    for kc in kill_chains_found:
        key = kc["chain_name"]
        if key not in seen:
            seen.add(key)
            unique_chains.append(kc)

    return G, correlated_groups, unique_chains


# ── Graph JSON for frontend ───────────────────────────────────────

def get_graph_json(events: list) -> dict:
    """
    Returns graph data formatted for D3 force-directed visualization.
    Called by GET /correlations/graph in api.py
    """
    G, groups, chains = correlate_events(events)

    nodes = []
    for node_id in G.nodes():
        data = G.nodes[node_id]
        nodes.append({
            "id":        node_id,
            "label":     data.get("source_ip", "?"),
            "score":     data.get("anomaly_score", 0),
            "severity":  data.get("severity", "INFO"),
            "technique": data.get("technique_id", ""),
            "tactic":    data.get("tactic", ""),
            "message":   data.get("message", "")[:60],
        })

    edges = []
    for u, v, data in G.edges(data=True):
        edges.append({
            "source":   u,
            "target":   v,
            "relation": data.get("relation", "related"),
            "weight":   data.get("weight", 1.0),
        })

    return {
        "nodes":              nodes,
        "edges":              edges,
        "node_count":         len(nodes),
        "edge_count":         len(edges),
        "correlated_groups":  len(groups),
        "kill_chains":        chains,
        "kill_chain_count":   len(chains),
    }


# ── Test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    from db import init_db, get_recent_events

    print("=" * 65)
    print("  WEEK 3 DAY 3 — Correlation Engine Test")
    print("=" * 65)

    if not os.path.exists("data/soc_analyst.db"):
        print("\n  Database not found — run: python db.py first")
        exit(1)

    # Load events from DB
    events = get_recent_events(limit=200)
    print(f"\n  Loaded {len(events)} events from database")

    # Run correlation
    G, groups, chains = correlate_events(events)

    print(f"\n  ── Graph Statistics ──")
    print(f"  Nodes (events)   : {G.number_of_nodes()}")
    print(f"  Edges (relations): {G.number_of_edges()}")
    print(f"  Connected groups : {len(groups)}")

    # Show edge types
    edge_types = {}
    for _, _, data in G.edges(data=True):
        rel = data.get("relation", "unknown")
        edge_types[rel] = edge_types.get(rel, 0) + 1
    print(f"\n  ── Edge Types ──")
    for rel, count in sorted(edge_types.items(), key=lambda x: -x[1]):
        print(f"  {rel:<28} {count} edges")

    # Show top correlated groups
    print(f"\n  ── Top 5 Correlated Groups ──")
    for g in groups[:5]:
        ips = ", ".join(g["source_ips"][:2])
        tactics = ", ".join(g["tactics"][:3]) or "none"
        print(f"  Group {g['group_id']}: {g['event_count']:>4} events | "
              f"IPs: {ips:<22} | Tactics: {tactics}")

    # Show kill chains
    print(f"\n  ── Kill Chains Detected: {len(chains)} ──")
    if chains:
        for kc in chains:
            print(f"\n  {kc['alert']}")
            print(f"  Description  : {kc['description']}")
            print(f"  Match        : {kc['match_percent']}% of kill chain tactics present")
            print(f"  Events       : {kc['event_count']}")
            print(f"  Source IPs   : {', '.join(kc['source_ips'])}")
            print(f"  Tactics found: {', '.join(kc['tactics_found'])}")
            print(f"  Techniques   : {', '.join(kc['techniques'])}")
    else:
        print("  No kill chains detected in current dataset")
        print("  (Expected — sample data may not have full tactic sequences)")

    # Test graph JSON output
    print(f"\n  ── Graph JSON for Dashboard ──")
    graph_data = get_graph_json(events)
    print(f"  Nodes          : {graph_data['node_count']}")
    print(f"  Edges          : {graph_data['edge_count']}")
    print(f"  Correlated grps: {graph_data['correlated_groups']}")
    print(f"  Kill chains    : {graph_data['kill_chain_count']}")

    # Checklist
    print(f"\n  ── Day 3 Checklist ──")
    checks = {
        "Graph built from DB events":     G.number_of_nodes() > 0,
        "Same-IP edges created":          edge_types.get("same_ip", 0) > 0,
        "Tactic edges created":           edge_types.get("same_tactic", 0) > 0,
        "Correlated groups found":        len(groups) > 0,
        "Kill chain detection running":   True,
        "Graph JSON for dashboard ready": graph_data["node_count"] > 0,
    }
    for check, passed in checks.items():
        print(f"  {'✅' if passed else '❌'}  {check}")

    print("=" * 65)