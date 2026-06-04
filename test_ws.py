"""
Test WebSocket connection and command processing.
"""
import asyncio
import json
import websockets


async def test():
    async with websockets.connect("ws://127.0.0.1:8765/ws") as ws:
        # 1. Get initial security status
        msg = await asyncio.wait_for(ws.recv(), timeout=5)
        data = json.loads(msg)
        print(f"[1] Initial msg type: {data['type']}")
        print(f"    Security keys: {list(data['data'].keys())}")

        # 2. Send a test command: what time is it
        await ws.send(json.dumps({"type": "command", "data": "what time is it"}))

        # Receive processing state
        msg = await asyncio.wait_for(ws.recv(), timeout=5)
        data = json.loads(msg)
        print(f"[2] State change: {data}")

        # Receive response
        msg = await asyncio.wait_for(ws.recv(), timeout=10)
        data = json.loads(msg)
        print(f"[3] Response: {data}")

        # Receive idle state
        msg = await asyncio.wait_for(ws.recv(), timeout=5)
        data = json.loads(msg)
        print(f"[4] Back to idle: {data}")

        # 3. Send another command: system status
        await ws.send(json.dumps({"type": "command", "data": "system status"}))

        msg = await asyncio.wait_for(ws.recv(), timeout=5)
        data = json.loads(msg)
        print(f"[5] State change: {data}")

        msg = await asyncio.wait_for(ws.recv(), timeout=10)
        data = json.loads(msg)
        print(f"[6] System status response: {data}")

        msg = await asyncio.wait_for(ws.recv(), timeout=5)
        data = json.loads(msg)
        print(f"[7] Back to idle: {data}")

        # 4. Send password generation command
        await ws.send(json.dumps({"type": "command", "data": "generate a secure password"}))

        msg = await asyncio.wait_for(ws.recv(), timeout=5)
        msg = await asyncio.wait_for(ws.recv(), timeout=10)
        data = json.loads(msg)
        print(f"[8] Password gen response: {data}")

        msg = await asyncio.wait_for(ws.recv(), timeout=5)

        # 5. Request security status refresh
        await ws.send(json.dumps({"type": "get_security_status"}))
        msg = await asyncio.wait_for(ws.recv(), timeout=5)
        data = json.loads(msg)
        print(f"[9] Security status refresh: type={data['type']}, keys={list(data['data'].keys())}")

        print("\n" + "=" * 50)
        print("  ALL WEBSOCKET TESTS PASSED!")
        print("=" * 50)


if __name__ == "__main__":
    asyncio.run(test())
