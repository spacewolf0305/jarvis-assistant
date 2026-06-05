"""
J.A.R.V.I.S — Web Server
FastAPI + WebSocket server for the HUD dashboard.
"""

import asyncio
import json
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

import config
from commands.router import CommandRouter
from security.security_dashboard import SecurityDashboard

app = FastAPI(title="JARVIS", version=config.VERSION)

# State
connected_clients = set()
security_dashboard = SecurityDashboard()
command_router = None  # Initialized after speaker is set


def init_router(speaker=None):
    """Initialize command router with speaker reference."""
    global command_router
    command_router = CommandRouter(speaker=speaker)


# ─── Static Files ──────────────────────────────────────────
app.mount("/css", StaticFiles(directory=str(config.FRONTEND_DIR / "css")), name="css")
app.mount("/js", StaticFiles(directory=str(config.FRONTEND_DIR / "js")), name="js")


@app.on_event("startup")
async def _start_background_tasks():
    """Launch the live telemetry / alert loop and background monitors."""
    asyncio.create_task(security_refresh_loop())

    # Auto-start continuous threat monitors so protection is on from boot
    if getattr(config, "AUTO_START_MONITORS", False) and command_router:
        for mon_attr in ("crypto_monitor", "process_monitor",
                         "ddos_monitor", "ransomware_monitor"):
            monitor = getattr(command_router, mon_attr, None)
            if monitor and hasattr(monitor, "start_monitor"):
                try:
                    monitor.start_monitor()
                except Exception:
                    pass


@app.get("/")
async def serve_index():
    """Serve the main HUD page."""
    return FileResponse(str(config.FRONTEND_DIR / "index.html"))


# ─── WebSocket ─────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time HUD communication."""
    await websocket.accept()
    connected_clients.add(websocket)

    try:
        # Send initial security status
        status = security_dashboard.get_status()
        await websocket.send_json({
            "type": "security_status",
            "data": status
        })

        while True:
            # Receive messages from HUD
            data = await websocket.receive_text()
            message = json.loads(data)

            if message["type"] == "command":
                # Process text command from HUD
                command_text = message.get("data", "")
                if command_text and command_router:
                    # Notify HUD that we're processing
                    await broadcast({
                        "type": "state",
                        "data": "processing"
                    })

                    # Route the command
                    response = await command_router.route(command_text)

                    # Speak the response aloud if speaker is available
                    if response and command_router.speaker:
                        command_router.speaker.speak(response)

                    # Send response to HUD
                    await broadcast({
                        "type": "response",
                        "data": response
                    })
                    await broadcast({
                        "type": "state",
                        "data": "idle"
                    })

            elif message["type"] == "push_to_talk":
                await broadcast({
                    "type": "state",
                    "data": "listening"
                })

            elif message["type"] == "get_security_status":
                status = security_dashboard.get_status()
                await websocket.send_json({
                    "type": "security_status",
                    "data": status
                })

            elif message["type"] == "settings_update":
                # Handle settings changes from HUD
                settings = message.get("data", {})
                if "gemini_api_key" in settings:
                    config.GEMINI_API_KEY = settings["gemini_api_key"]
                if "virustotal_api_key" in settings:
                    config.VIRUSTOTAL_API_KEY = settings["virustotal_api_key"]
                if "abuseipdb_api_key" in settings:
                    config.ABUSEIPDB_API_KEY = settings["abuseipdb_api_key"]

    except WebSocketDisconnect:
        connected_clients.discard(websocket)
    except Exception:
        connected_clients.discard(websocket)


async def broadcast(message):
    """Broadcast a message to all connected HUD clients."""
    disconnected = set()
    for client in connected_clients:
        try:
            await client.send_json(message)
        except Exception:
            disconnected.add(client)
    connected_clients.difference_update(disconnected)


# ─── Live telemetry helper ────────────────────────────────
def get_live_telemetry():
    """Snapshot of CPU / memory / network for real-time HUD streaming."""
    try:
        import psutil
        net = psutil.net_io_counters()
        return {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "mem_percent": psutil.virtual_memory().percent,
            "net_sent": net.bytes_sent,
            "net_recv": net.bytes_recv,
            "connections": len(psutil.net_connections(kind="inet")),
        }
    except Exception:
        return {}


# ─── Background Tasks: telemetry stream, security status, alerts ──
async def security_refresh_loop():
    """Stream live telemetry, refresh security status, and dispatch alerts.

    - Telemetry is pushed every few seconds for a real-time HUD.
    - Full security status is pushed less often.
    - New high-severity detections are dispatched (spoken + desktop toast)
      and broadcast to the HUD the moment they appear in the event store.
    """
    from security.alert_manager import get_alert_manager
    alert_mgr = get_alert_manager(
        speaker=command_router.speaker if command_router else None
    )

    tick = 0
    while True:
        try:
            await asyncio.sleep(2)
            tick += 1

            # Live telemetry every 2s
            telemetry = get_live_telemetry()
            if telemetry:
                await broadcast({"type": "telemetry", "data": telemetry})

            # New high-severity alerts — checked every cycle, pushed instantly
            for ev in alert_mgr.check_new_alerts():
                await broadcast({"type": "alert", "data": ev})

            # Full security status every ~30s (15 ticks * 2s)
            if tick % 15 == 0:
                await broadcast({
                    "type": "security_status",
                    "data": security_dashboard.get_status(),
                })
        except Exception:
            pass
