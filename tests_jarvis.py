"""
JARVIS feature test suite — runs everything testable without audio/Windows.
Run:  python3 -m tests_jarvis
"""
import sys, tempfile, os
from pathlib import Path

import security.event_store as es
from security.event_store import EventStore, Severity

PASS, FAIL = 0, 0
def check(name, cond):
    global PASS, FAIL
    mark = "PASS" if cond else "FAIL"
    if cond: PASS += 1
    else: FAIL += 1
    print(f"  [{mark}] {name}")
    return cond

# Use an isolated DB for the whole run
tmpdb = tempfile.mktemp(suffix=".db")
store = EventStore(db_path=tmpdb)
store.clear()
es._store = store

print("\n=== 1. EVENT STORE ===")
store.log_event("t","crypto_monitor", threat_type="Cryptojacking", message="m1",
                severity=Severity.HIGH, mitre_id="T1496") if False else None
# use the real signature
store.log_event("crypto_monitor", Severity.HIGH, "Cryptojacking", "miner found", mitre_id="T1496")
store.log_event("net", Severity.MEDIUM, "Rogue Device", "unknown dev", mitre_id="T1200")
store.log_event("ransom", Severity.CRITICAL, "Ransomware", "files encrypted", mitre_id="T1486")
allev = store.get_events(limit=50)
check("3 events stored", len(allev) == 3)
highplus = store.get_events(min_severity=Severity.HIGH, limit=50)
check("severity filter returns HIGH+CRITICAL only (2)", len(highplus) == 2)
summ = store.get_summary(hours=24)
check("summary counts total = 3", summ.get("Total") == 3)
check("summary has 1 critical", summ.get("Critical") == 1)

print("\n=== 2. PROCESS / FILELESS DETECTION LOGIC ===")
from security.process_monitor import ProcessMonitor
pm = ProcessMonitor()
cases = [
    ({"pid":1,"name":"powershell.exe","cmdline":["powershell.exe","-nop","-w","hidden","-enc","ABC123"],"exe":"c:\\windows\\system32\\powershell.exe"}, True, "encoded PowerShell flagged"),
    ({"pid":2,"name":"chrome.exe","cmdline":["chrome.exe","--type=renderer"],"exe":"c:\\program files\\chrome.exe"}, False, "legit chrome NOT flagged"),
    ({"pid":3,"name":"update.exe","cmdline":["update.exe"],"exe":"c:\\users\\bob\\appdata\\local\\temp\\update.exe"}, True, "temp-folder exe flagged"),
    ({"pid":4,"name":"certutil.exe","cmdline":["certutil.exe","-urlcache","-f","http://x/y.exe"],"exe":"c:\\windows\\system32\\certutil.exe"}, True, "certutil download flagged"),
]
for info, should_flag, label in cases:
    res = pm._assess(info)
    check(label, (res is not None) == should_flag)

print("\n=== 3. DETECTORS RUN ON REAL (LINUX) PROCESSES ===")
from security.crypto_monitor import CryptoMonitor
cm = CryptoMonitor()
try:
    r = cm.scan()
    check("crypto scan() runs on live processes without crashing", isinstance(r, str))
    print(f"        -> {r[:70]}")
except Exception as e:
    check(f"crypto scan() runs (got {type(e).__name__})", False)
try:
    r2 = pm.scan()
    check("process scan() runs on live processes without crashing", isinstance(r2, str))
    print(f"        -> {r2[:70]}")
except Exception as e:
    check(f"process scan() runs (got {type(e).__name__})", False)

print("\n=== 4. ALERT MANAGER ===")
from security.alert_manager import AlertManager
spoken = []
class MockSpeaker:
    def speak(self, t): spoken.append(t)
# Manager starts watching FIRST, then new detections arrive (real usage)
mgr = AlertManager(speaker=MockSpeaker(), min_severity=Severity.HIGH)
check("no alerts before any new detection", len(mgr.check_new_alerts()) == 0)
store.log_event("crypto_monitor", Severity.HIGH, "Cryptojacking", "live miner xmrig", mitre_id="T1496")
store.log_event("net2", Severity.MEDIUM, "Rogue Device", "ignore me", mitre_id="T1200")
store.log_event("ransom2", Severity.CRITICAL, "Ransomware", "files encrypting now", mitre_id="T1486")
disp = mgr.check_new_alerts()
check("alerts only HIGH+CRITICAL (2 of 3 new events)", len(disp) == 2)
check("spoke 2 alerts aloud", len(spoken) == 2)
check("critical prefix correct", any("Critical alert" in s for s in spoken))
check("no duplicate alerts on re-check", len(mgr.check_new_alerts()) == 0)

print("\n=== 5. PDF INCIDENT REPORT ===")
from security.incident_report import IncidentReport
rep = IncidentReport(output_dir=tempfile.mkdtemp())
path, msg = rep.generate(hours=24)
check("report path returned", bool(path))
check("PDF file exists on disk", path and os.path.exists(path))
if path and os.path.exists(path):
    with open(path, "rb") as f:
        head = f.read(5)
    check("file is a valid PDF (header)", head == b"%PDF-")
    check("PDF non-trivial size (>2KB)", os.path.getsize(path) > 2048)

print("\n=== 6. WAKE-WORD LISTENER (load + graceful degrade) ===")
from core.listener import Listener
states = []
lis = Listener(wake_word="jarvis", on_state_change=lambda s,d: states.append(s))
check("listener constructs", lis is not None)
# ready is True on a real machine (mic present), False in a headless sandbox —
# both are valid; we only require a clean boolean and no crash.
check("listener reports a readiness boolean", isinstance(lis.ready, bool))
lis.start()  # must not raise regardless of readiness
check("start() is safe to call", True)
if lis.ready:
    print("        -> mic + wake engine detected on this machine (good!)")
    lis.stop()
else:
    print("        -> no mic/engine here (expected in a sandbox)")

print("\n=== 7. BRUTE-FORCE DETECTION LOGIC ===")
from security.eventlog_monitor import assess_failures
from datetime import datetime, timedelta
now = datetime.now()
recs = [{"time": now - timedelta(seconds=50 - i*7), "event_id": 4625,
         "account": "admin", "source_ip": "10.0.0.66"} for i in range(6)]
recs.append({"time": now, "event_id": 4624, "account": "admin", "source_ip": "10.0.0.66"})
recs.append({"time": now, "event_id": 4625, "account": "guest", "source_ip": "10.0.0.5"})
findings = assess_failures(recs)
check("brute-force detected for admin", any(f["account"] == "admin" for f in findings))
check("single failure (guest) NOT flagged", not any(f["account"] == "guest" for f in findings))
check("admin flagged as compromised (success after fails)",
      any(f["account"] == "admin" and f["compromised"] for f in findings))

print("\n=== 8. ACTIVE RESPONSE SAFETY GUARDS ===")
from security.responder import Responder
r = Responder()
check("public IP is blockable", r._is_blockable_ip("185.220.101.45")[0] is True)
check("loopback refused", r._is_blockable_ip("127.0.0.1")[0] is False)
check("private LAN refused (no self-lockout)", r._is_blockable_ip("192.168.1.1")[0] is False)
check("invalid IP refused", r._is_blockable_ip("nope")[0] is False)
res = r.block_ip("185.220.101.45")
check("block defaults to SIMULATED (dry-run)", "SIMULATED" in res)
check("blocking a private IP is refused even when asked", "Refusing" in r.block_ip("192.168.1.10"))

print("\n" + "="*40)
print(f"  RESULTS: {PASS} passed, {FAIL} failed")
print("="*40)
sys.exit(1 if FAIL else 0)
