import sqlite3, json, os, datetime
import config

def _conn():
    os.makedirs(os.path.dirname(config.DATABASE), exist_ok=True)
    c = sqlite3.connect(config.DATABASE)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT, target_url TEXT NOT NULL, scan_date TEXT NOT NULL,
            security_score INTEGER, total_findings INTEGER, critical_count INTEGER, high_count INTEGER,
            medium_count INTEGER, low_count INTEGER, result_json TEXT NOT NULL)""")

def save_scan(result):
    s = result["summary"]
    with _conn() as c:
        cur = c.execute("""INSERT INTO scans (target_url, scan_date, security_score, total_findings, critical_count,
            high_count, medium_count, low_count, result_json) VALUES (?,?,?,?,?,?,?,?,?)""",
            (result["target_url"], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), s["score"],
             s["total_findings"], s["critical"], s["high"], s["medium"], s["low"], json.dumps(result)))
        return cur.lastrowid

def get_scan(scan_id):
    with _conn() as c:
        row = c.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    if not row: return None
    data = json.loads(row["result_json"])
    s = data.get("summary", {})
    if "risk_score" not in s:
        s["risk_score"] = 100 - s.get("score", 100)
        risk = s["risk_score"]
        if risk <= 10: s["risk_level"] = "LOW RISK"
        elif risk <= 25: s["risk_level"] = "MODERATE RISK"
        elif risk <= 50: s["risk_level"] = "ELEVATED RISK"
        elif risk <= 75: s["risk_level"] = "HIGH RISK"
        else: s["risk_level"] = "CRITICAL RISK"
    return {"scan_id": row["scan_id"], "scan_date": row["scan_date"], **data}

def list_scans():
    with _conn() as c:
        rows = c.execute("SELECT * FROM scans ORDER BY scan_id DESC LIMIT 200").fetchall()
        results = []
        for r in rows:
            d = dict(r)
            if "security_score" in d and d["security_score"] is not None:
                d["risk_score"] = 100 - d["security_score"]
            else:
                d["risk_score"] = 0
            results.append(d)
        return results

def delete_scan(scan_id):
    with _conn() as c:
        c.execute("DELETE FROM scans WHERE scan_id=?", (scan_id,))
