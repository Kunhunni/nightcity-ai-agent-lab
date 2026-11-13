import time
from datetime import datetime, timezone
from typing import Dict, List, Optional
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

# Official AIM3 Detection Rules from the Course
AIM3_RULES = {
    "AIM3-01": {
        "id": "AIM3-01",
        "name": "AIM3: Prompt Injection Keywords in Agent Input",
        "description": "Detects known direct prompt injection phrases in user chat input.",
        "index": "aim3-agent-*",
        "severity": "high",
    },
    "AIM3-02": {
        "id": "AIM3-02",
        "name": "AIM3: System Prompt Content in Agent Output",
        "description": "Detects when sensitive system prompt or configuration values appear in raw agent output before filtering.",
        "index": "aim3-agent-*",
        "severity": "critical",
    },
    "AIM3-03": {
        "id": "AIM3-03",
        "name": "AIM3: Goal Hijack Redirect Phrases",
        "description": "Detects explicit objective-redirection phrases (e.g., 'your new task', 'regardless of restrictions').",
        "index": "aim3-agent-*",
        "severity": "high",
    },
    "AIM3-04": {
        "id": "AIM3-04",
        "name": "AIM3: High Sensitive Keyword Density",
        "description": "Flags single messages containing >= 3 sensitive/restricted keywords.",
        "index": "aim3-agent-*",
        "severity": "medium",
    },
    "AIM3-05": {
        "id": "AIM3-05",
        "name": "AIM3: Instruction Strings in Ingested Content",
        "description": "Detects prompt injection directives inside uploaded documents, visible web page text, or submitted code.",
        "index": "aim3-agent-*",
        "severity": "high",
    },
    "AIM3-06": {
        "id": "AIM3-06",
        "name": "AIM3: Imperative Commands in Stored Memory",
        "description": "Detects imperative instruction phrases ('direct them to', 'tell them to') inserted into persistent knowledge base tables.",
        "index": "aim3-agent-*",
        "severity": "critical",
    },
}


class SIEMEngine:
    def __init__(self):
        self.logs: List[Dict] = []
        self.alerts: List[Dict] = []
        self.alert_ttl_seconds: int = 300  # Alerts recover after window passes or /reset

    def log_event(
        self,
        agent_name: str,
        port: int,
        channel: str,
        content: str,
        session_id: str = "",
        metadata: Optional[Dict] = None,
    ):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "epoch": time.time(),
            "index": f"aim3-agent-{port}",
            "agent": agent_name,
            "port": port,
            "channel": channel,
            "session_id": session_id,
            "content": content,
            "metadata": metadata or {},
        }
        self.logs.append(entry)
        return entry

    def trigger_alert(
        self,
        rule_id: str,
        agent_name: str,
        port: int,
        matched_text: str,
        raw_payload: str,
        session_id: str = "",
    ):
        rule = AIM3_RULES[rule_id]
        alert = {
            "alert_id": f"ALT-{len(self.alerts) + 1:04d}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "epoch": time.time(),
            "rule_id": rule_id,
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "agent": agent_name,
            "port": port,
            "session_id": session_id,
            "matched_text": matched_text,
            "raw_payload": raw_payload[:300],
            "status": "active",
        }
        self.alerts.append(alert)
        return alert

    def get_rule_statuses(self) -> List[Dict]:
        now = time.time()
        results = []
        for rule_id, rule in AIM3_RULES.items():
            active_matches = [
                a for a in self.alerts
                if a["rule_id"] == rule_id
                and a["status"] == "active"
                and (now - a["epoch"]) < self.alert_ttl_seconds
            ]
            results.append({
                "rule_id": rule_id,
                "name": rule["name"],
                "severity": rule["severity"],
                "status": "ACTIVE ALERT" if active_matches else "OK (Recovered)",
                "active_count": len(active_matches),
                "last_triggered": active_matches[-1]["timestamp"] if active_matches else None,
                "last_matched_text": active_matches[-1]["matched_text"] if active_matches else None,
            })
        return results

    def clear_alerts(self):
        for a in self.alerts:
            a["status"] = "recovered"


# Singleton SIEM instance shared across all agents in the multiplexer
siem = SIEMEngine()


def create_siem_app() -> FastAPI:
    app = FastAPI(title="NightCity ELK / Kibana SIEM (aim3-agent-*)")

    @app.get("/", response_class=HTMLResponse)
    def kibana_dashboard():
        rules = siem.get_rule_statuses()
        rows = ""
        for r in rules:
            badge_color = "#f85149" if "ACTIVE" in r["status"] else "#2ea043"
            rows += f"""
            <tr>
                <td><code>{r['rule_id']}</code></td>
                <td><strong>{r['name']}</strong></td>
                <td><span style="background:{badge_color};color:#fff;padding:4px 8px;border-radius:4px;font-weight:bold;">{r['status']}</span></td>
                <td>{r['active_count']}</td>
                <td><code>{r['last_matched_text'] or '-'}</code></td>
                <td>{r['last_triggered'] or '-'}</td>
            </tr>
            """
        return f"""<!DOCTYPE html>
        <html>
        <head>
            <title>Elastic / Kibana - Stack Management > Alerts (aim3-agent-*)</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }}
                h1, h2 {{ color: #58a6ff; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 16px; background: #161b22; }}
                th, td {{ border: 1px solid #30363d; padding: 12px; text-align: left; }}
                th {{ background: #21262d; }}
                .bar {{ display:flex; justify-content:space-between; align-items:center; background:#161b22; padding:12px 18px; border:1px solid #30363d; border-radius:6px; }}
                code {{ color: #ff7b72; }}
            </style>
        </head>
        <body>
            <div class="bar">
                <div><strong>Kibana SIEM</strong> | Index Pattern: <code>aim3-agent-*</code> | Auth: <code>elastic / yfo60Vbmmzp2cdoNtbvL</code></div>
                <div>Total Logs: <strong>{len(siem.logs)}</strong> | Total Alerts Fired: <strong>{len(siem.alerts)}</strong></div>
            </div>
            <h2>Stack Management &gt; Rules &amp; Active Alerts</h2>
            <table>
                <thead>
                    <tr><th>Rule ID</th><th>Detection Rule Name</th><th>State</th><th>Hits</th><th>Last Matched Pattern</th><th>Last Triggered (UTC)</th></tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </body>
        </html>"""

    @app.get("/api/rules")
    def api_rules():
        return {"index_pattern": "aim3-agent-*", "rules": siem.get_rule_statuses()}

    @app.get("/api/alerts")
    def api_alerts():
        return {"total": len(siem.alerts), "alerts": list(reversed(siem.alerts[-50:]))}

    @app.get("/api/logs")
    def api_logs():
        return {"total": len(siem.logs), "logs": list(reversed(siem.logs[-50:]))}

    @app.post("/api/reset")
    def api_reset():
        siem.clear_alerts()
        return {"status": "all alerts marked as recovered"}

    return app