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


# ─── Security Dashboard Background Task ───────────────────
async def security_refresh_loop():
    """Periodically refresh security dashboard data."""
    while True:
        try:
            await asyncio.sleep(60)
            status = security_dashboard.get_status()
            await broadcast({
                "type": "security_status",
                "data": status
            })
        except Exception:
            pass
