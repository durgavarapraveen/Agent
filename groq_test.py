import asyncio
import httpx

async def test_deepseek():
    api_key = "your_key_here"  # From .env
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            "https://api.deepseek.com/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": "You are a test. Respond with JSON: {\"test\": \"ok\"}"},
                    {"role": "user", "content": "Say ok"}
                ],
                "max_tokens": 100,
                "temperature": 0.1,
                "response_format": {"type": "json_object"}
            }
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:500]}")

asyncio.run(test_deepseek())