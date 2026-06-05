"""
J.A.R.V.I.S — Security Event Store
Central SQLite-backed log for all security detections.

Every detector writes events here via log_event(). The HUD, the voice
interface and the incident-report generator all read from this single
source of truth. Events carry a severity and an optional MITRE ATT&CK
technique reference so the system maps onto a recognised threat taxonomy.
"""

import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from enum import IntEnum


# ─── Severity levels ───────────────────────────────────────
class Severity(IntEnum):
    """Ordered so higher value = more serious (enables easy filtering)."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self):
        return self.name.capitalize()


# ─── MITRE ATT&CK technique reference ──────────────────────
# A small, curated map. Detectors reference these so reports speak the
# same language a SOC analyst would expect.
MITRE_TECHNIQUES = {
    "T1486": "Data Encrypted for Impact (Ransomware)",
    "T1496": "Resource Hijacking (Cryptojacking)",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1055": "Process Injection (Fileless)",
    "T1110": "Brute Force",
    "T1071": "Application Layer Protocol (C2 Beaconing)",
    "T1571": "Non-Standard Port (C2)",
    "T1498": "Network Denial of Service (DDoS)",
    "T1046": "Network Service Discovery (Port Scan)",
    "T1557": "Adversary-in-the-Middle (MitM/ARP Spoof)",
    "T1200": "Hardware Additions (New Network Device)",
    "T1078": "Valid Accounts (Credential Misuse)",
}

DB_PATH = Path(__file__).parent.parent / "data" / "jarvis_events.db"


class EventStore:
    """Thread-safe SQLite store for security events."""

    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path else DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self):
        # check_same_thread=False because detectors run on background threads;
        # we serialise writes ourselves with self._lock.
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT    NOT NULL,
                    source      TEXT    NOT NULL,
                    severity    INTEGER NOT NULL,
                    threat_type TEXT    NOT NULL,
                    mitre_id    TEXT,
                    message     TEXT    NOT NULL,
                    details     TEXT,
                    mitigation  TEXT,
                    resolved    INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity)"
            )

    def log_event(self, source, severity, threat_type, message,
                  mitre_id=None, details=None, mitigation=None):
        """Record a security event. Returns the new event's row id."""
        if isinstance(severity, Severity):
            severity = int(severity)
        ts = datetime.now().isoformat(timespec="seconds")
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO events
                    (timestamp, source, severity, threat_type,
                     mitre_id, message, details, mitigation, resolved)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (ts, source, severity, threat_type,
                 mitre_id, message, details, mitigation),
            )
            return cur.lastrowid

    def get_events(self, since=None, min_severity=None, limit=200,
                   unresolved_only=False):
        """Fetch events, newest first, with optional filters."""
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        if since is not None:
            query += " AND timestamp >= ?"
            params.append(since)
        if min_severity is not None:
            query += " AND severity >= ?"
            params.append(int(min_severity))
        if unresolved_only:
            query += " AND resolved = 0"
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_summary(self, hours=24):
        """Counts grouped by severity over the last N hours — for the HUD."""
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT severity, COUNT(*) AS n
                FROM events WHERE timestamp >= ?
                GROUP BY severity
                """,
                (since,),
            ).fetchall()
        summary = {s.label: 0 for s in Severity}
        total = 0
        for r in rows:
            summary[Severity(r["severity"]).label] = r["n"]
            total += r["n"]
        summary["Total"] = total
        return summary

    def resolve_event(self, event_id):
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE events SET resolved = 1 WHERE id = ?", (event_id,)
            )

    def clear(self):
        """Wipe all events (useful for tests / fresh start)."""
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM events")


# Module-level singleton so every detector shares one store.
_store = None


def get_store():
    global _store
    if _store is None:
        _store = EventStore()
    return _store


def mitre_label(mitre_id):
    """Human-readable name for a technique id, e.g. 'T1486' -> '... (Ransomware)'."""
    return MITRE_TECHNIQUES.get(mitre_id, "Uncategorized")


if __name__ == "__main__":
    # Quick self-test
    store = EventStore(db_path="/tmp/jarvis_test_events.db")
    store.clear()
    store.log_event("crypto_monitor", Severity.HIGH, "Cryptojacking",
                    "Sustained 97% CPU with connection to mining pool",
                    mitre_id="T1496",
                    details="Process: xmrig.exe (PID 4821)",
                    mitigation="Terminate process; block pool IP at firewall")
    store.log_event("ransomware_monitor", Severity.CRITICAL, "Ransomware",
                    "42 files modified in 2 seconds",
                    mitre_id="T1486")
    store.log_event("process_monitor", Severity.MEDIUM, "Fileless Malware",
                    "PowerShell launched with encoded command",
                    mitre_id="T1059.001")
    print("Summary (24h):", store.get_summary())
    print("\nRecent events:")
    for e in store.get_events():
        print(f"  [{Severity(e['severity']).label}] {e['threat_type']} "
              f"({e['mitre_id']}): {e['message']}")
