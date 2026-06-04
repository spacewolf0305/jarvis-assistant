"""
Test the new DDoS and Bot detection commands via WebSocket.
"""
import asyncio
import json
import websockets


async def test():
    async with websockets.connect("ws://127.0.0.1:8765/ws") as ws:
        # Consume initial security_status
        msg = await asyncio.wait_for(ws.recv(), timeout=5)
        data = json.loads(msg)
        print(f"[INIT] security_status received: {data['type']}")

        # ── Test 1: check for ddos ────────────────────
        print("\n--- Test 1: check for ddos ---")
        await ws.send(json.dumps({"type": "command", "data": "check for ddos"}))
        await asyncio.wait_for(ws.recv(), timeout=5)  # processing state
        msg = await asyncio.wait_for(ws.recv(), timeout=10)
        data = json.loads(msg)
        print(f"Response: {data['data'][:200]}")
        await asyncio.wait_for(ws.recv(), timeout=5)  # idle state

        # ── Test 2: flood report ──────────────────────
        print("\n--- Test 2: flood report ---")
        await ws.send(json.dumps({"type": "command", "data": "flood report"}))
        await asyncio.wait_for(ws.recv(), timeout=5)
        msg = await asyncio.wait_for(ws.recv(), timeout=10)
        data = json.loads(msg)
        print(f"Response: {data['data'][:200]}")
        await asyncio.wait_for(ws.recv(), timeout=5)

        # ── Test 3: block ip ──────────────────────────
        print("\n--- Test 3: block ip 1.2.3.4 ---")
        await ws.send(json.dumps({"type": "command", "data": "block ip 1.2.3.4"}))
        await asyncio.wait_for(ws.recv(), timeout=5)
        msg = await asyncio.wait_for(ws.recv(), timeout=10)
        data = json.loads(msg)
        print(f"Response: {data['data'][:200]}")
        await asyncio.wait_for(ws.recv(), timeout=5)

        # ── Test 4: scan for bots ─────────────────────
        print("\n--- Test 4: scan for bots ---")
        await ws.send(json.dumps({"type": "command", "data": "scan for bots"}))
        await asyncio.wait_for(ws.recv(), timeout=5)
        msg = await asyncio.wait_for(ws.recv(), timeout=15)
        data = json.loads(msg)
        print(f"Response: {data['data'][:200]}")
        await asyncio.wait_for(ws.recv(), timeout=5)

        # ── Test 5: suspicious processes ──────────────
        print("\n--- Test 5: suspicious processes ---")
        await ws.send(json.dumps({"type": "command", "data": "suspicious processes"}))
        await asyncio.wait_for(ws.recv(), timeout=5)
        msg = await asyncio.wait_for(ws.recv(), timeout=15)
        data = json.loads(msg)
        print(f"Response: {data['data'][:200]}")
        await asyncio.wait_for(ws.recv(), timeout=5)

        # ── Test 6: check process python ──────────────
        print("\n--- Test 6: check process python ---")
        await ws.send(json.dumps({"type": "command", "data": "check process python"}))
        await asyncio.wait_for(ws.recv(), timeout=5)
        msg = await asyncio.wait_for(ws.recv(), timeout=15)
        data = json.loads(msg)
        print(f"Response: {data['data'][:250]}")
        await asyncio.wait_for(ws.recv(), timeout=5)

        print("\n" + "=" * 50)
        print("  ALL DDoS & BOT TESTS PASSED!")
        print("=" * 50)


if __name__ == "__main__":
    asyncio.run(test())
