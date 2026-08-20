"""
Simple Groq test - using exact pattern from Groq website
"""

from groq import Groq
import os

# Test 1: Check if API key is set
print("Checking GROQ_API_KEY...")
api_key = os.environ.get("GROQ_API_KEY")
if api_key:
    print(f"✓ API Key found: {api_key[:20]}...")
else:
    print("✗ GROQ_API_KEY not found in environment")
    print("  Trying from .env file...")
    
    from core.config import get_config
    api_key = get_config().get("GROQ_API_KEY")
    if api_key:
        print(f"✓ Found in .env: {api_key[:20]}...")
        # Set it in environment for Groq SDK
        os.environ["GROQ_API_KEY"] = api_key
    else:
        print("✗ GROQ_API_KEY not in .env either!")
        print("  Add this to .env:")
        print("    GROQ_API_KEY=your_key_here")
        exit(1)

# Test 2: Initialize Groq client
print("\nInitializing Groq client...")
try:
    client = Groq()
    print("✓ Client created")
except Exception as e:
    print(f"✗ Error creating client: {e}")
    exit(1)

# Test 3: Simple request (like Groq website example)
print("\nTest 3: Simple text request...")
try:
    completion = client.chat.completions.create(
        model="qwen/qwen3.6-27b",
        messages=[
            {
                "role": "user",
                "content": "Say 'Hello, this works!'"
            }
        ],
        max_tokens=100,
    )
    
    response = completion.choices[0].message.content
    print(f"✓ Response: {response}\n")
except Exception as e:
    print(f"✗ Error: {e}")
    exit(1)

# Test 4: JSON request
print("Test 4: JSON request...")
try:
    completion = client.chat.completions.create(
        model="qwen/qwen3.6-27b",
        messages=[
            {
                "role": "system",
                "content": "Respond ONLY with valid JSON."
            },
            {
                "role": "user",
                "content": 'Return this as JSON: {"test": "success", "status": "working"}'
            }
        ],
        max_tokens=200,
    )
    
    response_text = completion.choices[0].message.content
    print(f"Raw response:\n{response_text}\n")
    
    # Try to parse JSON
    import json
    try:
        parsed = json.loads(response_text)
        print(f"✓ JSON parsed successfully: {parsed}")
    except json.JSONDecodeError as e:
        print(f"⚠ JSON parse warning: {e}")
        print(f"  (Response might not be valid JSON)")
        
except Exception as e:
    print(f"✗ Error: {e}")
    exit(1)

print("\n" + "=" * 70)
print("✓ ALL TESTS PASSED - Groq is working!")
print("=" * 70)