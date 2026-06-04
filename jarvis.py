"""
J.A.R.V.I.S — Main Entry Point
Cybersecurity AI Voice Assistant for Windows
"""

import asyncio
import io
import sys
import threading
import time
import webbrowser
from datetime import datetime

# Fix Windows console encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', write_through=True)
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', write_through=True)

import uvicorn

import config
from core.listener import Listener
from core.speaker import Speaker
from server import app, init_router, broadcast


def get_greeting():
    """Get time-appropriate greeting."""
    hour = datetime.now().hour
    if 5 <= hour < 12:
        return config.GREETINGS["morning"]
    elif 12 <= hour < 17:
        return config.GREETINGS["afternoon"]
    elif 17 <= hour < 21:
        return config.GREETINGS["evening"]
    else:
        return config.GREETINGS["night"]


def print_banner():
    """Print the JARVIS startup banner."""
    print("\033[96m")
    print("  +====================================================+")
    print("  |                                                    |")
    print("  |          J . A . R . V . I . S    v2.0             |")
    print("  |                                                    |")
    print("  |      Cybersecurity AI Voice Assistant              |")
    print("  |                                                    |")
    print("  +====================================================+")
    print("\033[0m")
    print(f"  Server: http://{config.SERVER_HOST}:{config.SERVER_PORT}")
    print(f"  Wake Word: '{config.WAKE_WORD}'")
    gemini_status = '[OK] Configured' if config.GEMINI_API_KEY else '[--] Not set (AI features limited)'
    vt_status = '[OK] Configured' if config.VIRUSTOTAL_API_KEY else '[--] Not set (set VIRUSTOTAL_API_KEY)'
    abuse_status = '[OK] Configured' if config.ABUSEIPDB_API_KEY else '[--] Not set (set ABUSEIPDB_API_KEY)'
    print(f"  Gemini API: {gemini_status}")
    print(f"  VirusTotal: {vt_status}")
    print(f"  AbuseIPDB:  {abuse_status}")
    print()


def run_voice_loop(speaker, listener):
    """Run the voice command processing loop."""
    from commands.router import CommandRouter

    router = CommandRouter(speaker=speaker)

    while True:
        command = listener.get_command(timeout=1)
        if command:
            print(f"\033[93m  [CMD] {command}\033[0m")

            # Route command in async context
            loop = asyncio.new_event_loop()
            try:
                response = loop.run_until_complete(router.route(command))
                if response:
                    print(f"\033[96m  [JARVIS] {response}\033[0m")
                    speaker.speak(response)

                    # Broadcast to HUD
                    asyncio.run_coroutine_threadsafe(
                        broadcast({"type": "response", "data": response}),
                        main_loop
                    )
                    asyncio.run_coroutine_threadsafe(
                        broadcast({"type": "state", "data": "idle"}),
                        main_loop
                    )
            except Exception as e:
                print(f"\033[91m  [ERROR] {e}\033[0m")
            finally:
                loop.close()


# Global event loop reference
main_loop = None


def main():
    """Main entry point — start JARVIS."""
    global main_loop

    print_banner()

    # Initialize speaker
    print("  \033[90m[*] Initializing speech engine...\033[0m")
    speaker = Speaker(
        rate=config.VOICE_RATE,
        volume=config.VOICE_VOLUME,
        preferred_gender=config.PREFERRED_VOICE
    )

    # Initialize server command router
    init_router(speaker=speaker)

    # Initialize listener
    print("  \033[90m[*] Initializing microphone...\033[0m")

    def on_state_change(state, data):
        if state == "command_received":
            print(f"\033[93m  [HEARD] {data}\033[0m")
        elif state == "error":
            print(f"\033[91m  [MIC ERROR] {data}\033[0m")

    try:
        listener = Listener(
            wake_word=config.WAKE_WORD,
            on_state_change=on_state_change
        )
    except Exception as e:
        print(f"\033[91m  [ERROR] Microphone initialization failed: {e}\033[0m")
        print("  \033[90m  Make sure a microphone is connected and PyAudio is installed.\033[0m")
        print("  \033[90m  JARVIS will still work via the HUD text input.\033[0m")
        listener = None

    # Greeting
    greeting = get_greeting()
    print(f"\n  \033[96m{greeting}\033[0m\n")
    speaker.speak(greeting)

    # Start voice listener
    if listener:
        listener.start()
        print("  [OK] Voice listener active -- say 'Jarvis' to begin")

        # Start voice processing thread
        voice_thread = threading.Thread(
            target=run_voice_loop,
            args=(speaker, listener),
            daemon=True
        )
        voice_thread.start()

    # Open browser to HUD
    def open_browser():
        time.sleep(2)
        webbrowser.open(f"http://{config.SERVER_HOST}:{config.SERVER_PORT}")

    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()

    # Start FastAPI server
    print(f"  [OK] HUD Dashboard: http://{config.SERVER_HOST}:{config.SERVER_PORT}")
    print()
    print("  Press Ctrl+C to shutdown JARVIS")
    print()

    try:
        uvicorn_config = uvicorn.Config(
            app=app,
            host=config.SERVER_HOST,
            port=config.SERVER_PORT,
            log_level="warning",
        )
        server = uvicorn.Server(uvicorn_config)
        main_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(main_loop)
        main_loop.run_until_complete(server.serve())
    except KeyboardInterrupt:
        print("\n  \033[96m  JARVIS shutting down. Goodbye, sir.\033[0m")
        speaker.speak("Shutting down. Goodbye, sir.")
        time.sleep(2)
    finally:
        speaker.stop()
        if listener:
            listener.stop()


if __name__ == "__main__":
    main()
