"""
storage/db.py
Livello di persistenza per il sistema di detection ransomware.
Tre tabelle:
  - events:    ogni singolo evento grezzo del file system (create/modify/delete/move)
  - alerts:    alert generati dal detection engine (superamento soglia)
  - incidents: raggruppamento di alert correlati, con stato del contenimento
"""
import sqlite3
import threading
import time
import json
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "events.db")
_lock = threading.Lock()


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        event_type TEXT NOT NULL,      -- created / modified / deleted / moved
        path TEXT NOT NULL,
        is_decoy INTEGER NOT NULL DEFAULT 0,
        entropy REAL,
        size INTEGER,
        extension TEXT,
        pid INTEGER,
        process_name TEXT
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        severity TEXT NOT NULL,        -- low / medium / high / critical
        reason TEXT NOT NULL,
        event_ids TEXT NOT NULL,       -- JSON list of related event ids
        incident_id INTEGER
    );

    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_ts REAL NOT NULL,
        ended_ts REAL,
        status TEXT NOT NULL DEFAULT 'active',   -- active / contained / resolved
        containment_actions TEXT,                -- JSON list of actions taken
        summary TEXT
    );
    """)
    conn.commit()
    conn.close()


def insert_event(event_type, path, is_decoy=False, entropy=None, size=None,
                  extension=None, pid=None, process_name=None):
    with _lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO events (ts, event_type, path, is_decoy, entropy, size, extension, pid, process_name)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (time.time(), event_type, path, int(is_decoy), entropy, size, extension, pid, process_name)
        )
        conn.commit()
        eid = cur.lastrowid
        conn.close()
        return eid


def insert_alert(severity, reason, event_ids, incident_id=None):
    with _lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO alerts (ts, severity, reason, event_ids, incident_id) VALUES (?, ?, ?, ?, ?)",
            (time.time(), severity, reason, json.dumps(event_ids), incident_id)
        )
        conn.commit()
        aid = cur.lastrowid
        conn.close()
        return aid


def open_incident(summary=""):
    with _lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO incidents (started_ts, status, summary) VALUES (?, 'active', ?)",
            (time.time(), summary)
        )
        conn.commit()
        iid = cur.lastrowid
        conn.close()
        return iid


def update_incident(incident_id, status=None, containment_actions=None):
    conn = get_conn()
    cur = conn.cursor()
    fields, values = [], []
    if status:
        fields.append("status = ?")
        values.append(status)
        if status in ("contained", "resolved"):
            fields.append("ended_ts = ?")
            values.append(time.time())
    if containment_actions is not None:
        fields.append("containment_actions = ?")
        values.append(json.dumps(containment_actions))
    values.append(incident_id)
    cur.execute(f"UPDATE incidents SET {', '.join(fields)} WHERE id = ?", values)
    conn.commit()
    conn.close()


def get_recent_events(limit=200):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_alerts(limit=100):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_incidents():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM incidents ORDER BY started_ts DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_incident_timeline(incident_id):
    """Ricostruisce la sequenza temporale di un incidente per il replay."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM alerts WHERE incident_id = ? ORDER BY ts ASC", (incident_id,))
    alerts = [dict(r) for r in cur.fetchall()]
    event_ids = []
    for a in alerts:
        event_ids.extend(json.loads(a["event_ids"]))
    events = []
    if event_ids:
        q = f"SELECT * FROM events WHERE id IN ({','.join('?' * len(event_ids))}) ORDER BY ts ASC"
        cur.execute(q, event_ids)
        events = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"alerts": alerts, "events": events}


def reset_db():
    """Utile per demo ripetute: svuota tutte le tabelle."""
    with _lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.executescript("DELETE FROM events; DELETE FROM alerts; DELETE FROM incidents;")
        conn.commit()
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database inizializzato in {DB_PATH}")
