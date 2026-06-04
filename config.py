"""
J.A.R.V.I.S — Configuration
Central configuration for the voice assistant.
"""

import os
from pathlib import Path

# ─── General ───────────────────────────────────────────────
APP_NAME = "JARVIS"
VERSION = "2.0.0"
WAKE_WORD = "jarvis"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8765

# ─── Paths ─────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
FRONTEND_DIR = BASE_DIR / "frontend"
USER_HOME = Path(os.path.expanduser("~"))
SCREENSHOT_DIR = USER_HOME / "Desktop"

# ─── Voice Settings ────────────────────────────────────────
VOICE_RATE = 175          # Words per minute
VOICE_VOLUME = 1.0        # 0.0 to 1.0
PREFERRED_VOICE = "female"  # "male" or "female"
LISTEN_TIMEOUT = 5        # Seconds to wait for speech
PHRASE_TIMEOUT = 10       # Max phrase duration

# ─── AI Settings ───────────────────────────────────────────
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-2.0-flash"
MAX_CONVERSATION_HISTORY = 10

# ─── Security API Keys (free tiers) ───────────────────────
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# ─── App Registry ──────────────────────────────────────────
# Maps spoken names → executable names/paths
APP_REGISTRY = {
    "chrome": "chrome",
    "google chrome": "chrome",
    "firefox": "firefox",
    "brave": "brave",
    "edge": "msedge",
    "notepad": "notepad",
    "calculator": "calc",
    "calc": "calc",
    "vs code": "code",
    "visual studio code": "code",
    "file explorer": "explorer",
    "explorer": "explorer",
    "task manager": "taskmgr",
    "command prompt": "cmd",
    "cmd": "cmd",
    "powershell": "powershell",
    "spotify": "spotify",
    "word": "winword",
    "excel": "excel",
    "powerpoint": "powerpnt",
    "paint": "mspaint",
    "snipping tool": "snippingtool",
    "settings": "ms-settings:",
    "control panel": "control",
    "discord": "discord",
    "telegram": "telegram",
    "vlc": "vlc",
    "obs": "obs64",
    "steam": "steam",
}

# ─── Folder Shortcuts ──────────────────────────────────────
FOLDER_SHORTCUTS = {
    "documents": USER_HOME / "Documents",
    "my documents": USER_HOME / "Documents",
    "downloads": USER_HOME / "Downloads",
    "my downloads": USER_HOME / "Downloads",
    "desktop": USER_HOME / "Desktop",
    "my desktop": USER_HOME / "Desktop",
    "pictures": USER_HOME / "Pictures",
    "my pictures": USER_HOME / "Pictures",
    "videos": USER_HOME / "Videos",
    "my videos": USER_HOME / "Videos",
    "music": USER_HOME / "Music",
    "my music": USER_HOME / "Music",
    "home": USER_HOME,
}

# ─── Security Settings ─────────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1433, 1434, 3306, 3389,
    5432, 5900, 8080, 8443, 8888, 9090
]

RISKY_PORTS = {
    21: "FTP — File transfer, often unencrypted",
    23: "Telnet — Unencrypted remote access (CRITICAL)",
    135: "RPC — Windows Remote Procedure Call",
    139: "NetBIOS — File sharing, potential exploit vector",
    445: "SMB — File sharing, WannaCry attack vector (CRITICAL)",
    1433: "MSSQL — Database exposed",
    3306: "MySQL — Database exposed",
    3389: "RDP — Remote Desktop, brute-force target (CRITICAL)",
    5432: "PostgreSQL — Database exposed",
    5900: "VNC — Remote desktop, often weak auth",
}

# ─── Time-based Greetings ──────────────────────────────────
GREETINGS = {
    "morning": "Good morning, sir. JARVIS online and ready.",
    "afternoon": "Good afternoon, sir. Systems operational.",
    "evening": "Good evening, sir. All systems standing by.",
    "night": "Working late, sir? JARVIS is at your service.",
}
