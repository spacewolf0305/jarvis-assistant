import asyncio
from commands.router import CommandRouter

async def run_tests():
    router = CommandRouter()
    
    print("Testing CommandRouter...")
    
    commands = [
        "what time is it",
        "system status",
        "battery",
        "generate a secure password",
        "check wifi security",
    ]
    
    for cmd in commands:
        print(f"\n--- Command: '{cmd}' ---")
        try:
            response = await router.route(cmd)
            print(f"Response: {response}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(run_tests())
