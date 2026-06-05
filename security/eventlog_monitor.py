"""
J.A.R.V.I.S — Windows Security Event Log Monitor
Detects credential brute-force and suspicious logon patterns by watching the
Windows Security event log.

Signals:
  - Event ID 4625  (failed logon)  -> brute-force when N failures from the same
                                       account/source within a time window
  - Event ID 4624  (successful logon) right after a burst of 4625s
                                       -> possible successful brute-force

The detection logic (`assess_failures`) is a pure function over a list of
logon records, so it is fully unit-testable on any OS. The Windows-specific
log reading (via pywin32) is isolated and guarded so the module always loads.

MITRE: T1110 (Brute Force), T1078 (Valid Accounts)
"""

import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from security.event_store import get_store, Severity

# ── Guarded Windows-only import ──────────────────────────────
try:
    import win32evtlog          # part of pywin32
    WINLOG_OK = True
except Exception:
    WINLOG_OK = False

# Detection thresholds
FAIL_THRESHOLD = 5             # failed logons...
FAIL_WINDOW_SECONDS = 120      # ...within this window => brute force
POLL_INTERVAL = 10             # seconds between log reads


def assess_failures(records, threshold=FAIL_THRESHOLD,
                    window_seconds=FAIL_WINDOW_SECONDS):
    """Pure logic: given logon records, return brute-force findings.

    Each record is a dict: {time: datetime, event_id: int,
                            account: str, source_ip: str}
    Returns a list of findings (dicts) — one per offending account/source
    that exceeded the threshold within the window.
    """
    # Group failed logons (4625) by (account, source_ip)
    groups = defaultdict(list)
    successes = []
    for r in records:
        if r.get("event_id") == 4625:
            key = (r.get("account", "?"), r.get("source_ip", "?"))
            groups[key].append(r["time"])
        elif r.get("event_id") == 4624:
            successes.append(r)

    findings = []
    for (account, source_ip), times in groups.items():
        times = sorted(times)
        # Sliding window: is there any window_seconds span with >= threshold?
        dq = deque()
        peak = 0
        for t in times:
            dq.append(t)
            while dq and (t - dq[0]).total_seconds() > window_seconds:
                dq.popleft()
            peak = max(peak, len(dq))
        if peak >= threshold:
            # Was there a successful logon for this account shortly after?
            compromised = any(
                s.get("account") == account and
                s["time"] >= times[0]
                for s in successes
            )
            findings.append({
                "account": account,
                "source_ip": source_ip,
                "fail_count": len(times),
                "peak_in_window": peak,
                "compromised": compromised,
            })
    return findings


class EventLogMonitor:
    """Continuously watches the Windows Security log for brute-force."""

    def __init__(self):
        self.store = get_store()
        self._running = False
        self._thread = None
        self._alerted = set()        # (account, source_ip) already reported
        self._last_record_time = None

    def available(self):
        return WINLOG_OK

    # ── Read recent Security-log logon events ──
    def _read_recent(self, max_records=300):
        """Return recent 4624/4625 records as normalized dicts (Windows only)."""
        if not WINLOG_OK:
            return []
        records = []
        try:
            h = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | \
                win32evtlog.EVENTLOG_SEQUENTIAL_READ
            read = 0
            while read < max_records:
                events = win32evtlog.ReadEventLog(h, flags, 0)
                if not events:
                    break
                for ev in events:
                    eid = ev.EventID & 0xFFFF
                    if eid not in (4624, 4625):
                        continue
                    data = ev.StringInserts or []
                    account = data[5] if len(data) > 5 else "?"
                    source_ip = data[18] if len(data) > 18 else "?"
                    records.append({
                        "time": ev.TimeGenerated,
                        "event_id": eid,
                        "account": account,
                        "source_ip": source_ip,
                    })
                    read += 1
            win32evtlog.CloseEventLog(h)
        except Exception:
            pass
        return records

    def scan(self):
        """One-shot: assess recent logon history for brute-force."""
        if not WINLOG_OK:
            return ("Sir, Windows event log access requires the 'pywin32' "
                    "package, and this feature runs on Windows only.")
        records = self._read_recent()
        findings = assess_failures(records)
        if not findings:
            return "No brute-force activity detected, sir. Logon history is clean."
        for f in findings:
            self._record(f)
        lines = [
            f"{f['fail_count']} failed logons for '{f['account']}' "
            f"from {f['source_ip']}" + (" — ACCOUNT MAY BE COMPROMISED"
                                        if f["compromised"] else "")
            for f in findings
        ]
        return "Warning, sir. Brute-force activity detected:\n" + "\n".join(lines)

    def _record(self, f):
        key = (f["account"], f["source_ip"])
        if key in self._alerted:
            return
        self._alerted.add(key)
        sev = Severity.CRITICAL if f["compromised"] else Severity.HIGH
        mitigation = (
            f"Block source IP {f['source_ip']} at the firewall and lock the "
            f"'{f['account']}' account. Enforce MFA and review RDP exposure."
        )
        if f["compromised"]:
            mitigation = ("ACCOUNT LIKELY COMPROMISED. " + mitigation +
                          " Force a password reset and audit recent activity.")
        self.store.log_event(
            source="eventlog_monitor",
            severity=sev,
            threat_type="Credential Brute-Force",
            message=(f"{f['fail_count']} failed logons for '{f['account']}' "
                     f"from {f['source_ip']}"),
            mitre_id="T1078" if f["compromised"] else "T1110",
            details=f"Peak {f['peak_in_window']} failures within "
                    f"{FAIL_WINDOW_SECONDS}s window.",
            mitigation=mitigation,
        )

    # ── Continuous monitoring ──
    def start_monitor(self):
        if not WINLOG_OK:
            return ("Sir, Windows event log monitoring requires 'pywin32' "
                    "and runs on Windows only.")
        if self._running:
            return "Event log monitor is already active, sir."
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return "Event log monitor activated, sir. Watching for brute-force logons."

    def stop_monitor(self):
        self._running = False
        return "Event log monitor deactivated, sir."

    def _loop(self):
        while self._running:
            try:
                records = self._read_recent()
                for f in assess_failures(records):
                    self._record(f)
            except Exception:
                pass
            time.sleep(POLL_INTERVAL)

    def get_status(self):
        if not self._running:
            return "Event log monitor is offline, sir."
        return "Event log monitor active. Watching Security log for brute-force."


if __name__ == "__main__":
    # Self-test of the pure detection logic with synthetic logon records
    now = datetime.now()
    recs = []
    # 6 failed logons for 'admin' from one IP within 60s -> brute force
    for i in range(6):
        recs.append({"time": now - timedelta(seconds=60 - i * 8),
                     "event_id": 4625, "account": "admin",
                     "source_ip": "10.0.0.66"})
    # then a success -> compromised
    recs.append({"time": now, "event_id": 4624, "account": "admin",
                 "source_ip": "10.0.0.66"})
    # a couple of harmless failures for 'guest'
    recs.append({"time": now, "event_id": 4625, "account": "guest",
                 "source_ip": "10.0.0.5"})

    for f in assess_failures(recs):
        tag = "COMPROMISED" if f["compromised"] else "brute-force"
        print(f"[{tag}] {f['account']} from {f['source_ip']}: "
              f"{f['fail_count']} fails (peak {f['peak_in_window']})")
