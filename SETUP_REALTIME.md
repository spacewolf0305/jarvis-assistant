# JARVIS — Real-Time Upgrade: Setup & Test Guide

This covers the hands-free wake word, real-time alerting, live telemetry, and
the detect → mitigate → report pipeline added in this session.

## What changed

**New files**
- `security/alert_manager.py` — polls the event store and dispatches new
  HIGH/CRITICAL detections: speaks them, raises a desktop notification, and
  pushes them to the HUD.
- (already in your tree) `security/event_store.py`, `crypto_monitor.py`,
  `process_monitor.py`, `incident_report.py`.

**Rewritten**
- `core/listener.py` — always-on, hands-free wake-word listener. Two stages:
  a lightweight wake engine (Porcupine → openWakeWord → Vosk fallback, auto-
  selected) listens for "Jarvis", then the bundled Vosk model transcribes the
  command. **No spacebar required.** Works in the background / unfocused.

**Edited**
- `server.py` — live telemetry + alert dispatch loop, and a startup hook that
  actually launches it (it was defined but never started before). Optional
  auto-start of background monitors.
- `config.py` — wake-engine + alert settings.
- `frontend/js/main.js` — handles `telemetry` and `alert` messages.
- `requirements.txt` — vosk, pvporcupine, openwakeword, numpy, plyer, reportlab.

## Install

```powershell
pip install -r requirements.txt
```

`pvporcupine` and `openwakeword` are optional. If neither is installed, the
listener automatically falls back to Vosk keyword spotting (less accurate but
no extra setup, and it reuses the model you already bundle).

### (Recommended) Porcupine for best accuracy
1. Get a free access key at https://console.picovoice.ai
2. Set it: `setx PORCUPINE_ACCESS_KEY "your-key-here"` (reopen the terminal)

## Configure (config.py)

```python
WAKE_ENGINE = "auto"          # auto | porcupine | openwakeword | vosk
ALERT_MIN_SEVERITY = 3        # 3 = HIGH, 4 = CRITICAL-only
ALERT_SPEAK = True
AUTO_START_MONITORS = True    # monitors run from launch
```

## Test plan (on your Windows machine)

1. **Wake word (no spacebar):**
   - Run `python jarvis.py`. The banner should print the chosen wake engine.
   - With the window NOT focused, say: **"Jarvis, what time is it?"**
   - Expect: it wakes, transcribes, and answers. If it mis-hears, try the
     Porcupine engine (most accurate).

2. **New detectors (voice or HUD text):**
   - "Jarvis, scan for cryptojacking"
   - "Jarvis, scan for fileless malware" (try opening PowerShell with
     `powershell -nop -w hidden -enc <base64>` in a test VM to trigger it)

3. **Real-time alerts:**
   - With `AUTO_START_MONITORS = True`, trigger a detector (e.g. the ransomware
     canary by rapidly creating/renaming files in a watched folder).
   - Expect: JARVIS speaks the alert, a Windows notification pops, and the HUD
     banner/event log updates within ~2s.

4. **Live telemetry:**
   - Open the HUD. The System Status panel's CPU / RAM values and the
     Security panel's CONNECTIONS count update every 2s automatically.
   - A red alert banner slides in at the top whenever a HIGH/CRITICAL
     detection fires (auto-dismisses after 8s). All HUD elements are wired —
     no manual edits needed.

5. **Incident report:**
   - "Jarvis, generate an incident report"
   - Expect a PDF in the `reports/` folder (see the sample produced in chat).

## Known notes
- Module self-tests run via `python -m security.process_monitor`
  (not `python security/process_monitor.py`).
- The one-shot crypto `scan()` keys off miner signatures / pool connections;
  sustained-CPU detection is handled by the continuous monitor.
- Desktop notifications need `plyer` (cross-platform) or `win10toast` (Windows).
