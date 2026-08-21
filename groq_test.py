#!/usr/bin/env python3
"""Test DeepSeek API directly to debug response issues."""

import asyncio
import json
import httpx
import logging
from agents.llm_client import DeepSeekProvider

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(name)s] %(levelname)s: %(message)s'
)

async def test_deepseek():
    """Test DeepSeek provider"""
    try:
        provider = DeepSeekProvider(
            api_key="your-key-here",  # ← Set this
            small_model="deepseek-chat",
            large_model="deepseek-chat",
            base_url="https://api.deepseek.com"
        )
        
        print("\n" + "="*60)
        print("Testing DeepSeek Provider")
        print("="*60 + "\n")
        
        # Test 1: Simple text generation
        print("TEST 1: Simple text generation")
        print("-" * 60)
        text_result = await provider.generate(
            "Say hello in JSON format",
            tier=None,
            system="You are a helpful assistant.",
            max_tokens=100
        )
        print(f"Result: {text_result}\n")
        
        # Test 2: JSON generation with small prompt
        print("TEST 2: JSON generation (small)")
        print("-" * 60)
        json_result = await provider.generate_json(
            'Return: {"status": "ok"}',
            system="Respond only with JSON.",
            max_tokens=100
        )
        print(f"Result: {json.dumps(json_result, indent=2)}\n")
        
        # Test 3: JSON generation with complex prompt
        print("TEST 3: JSON generation (complex)")
        print("-" * 60)
        json_result2 = await provider.generate_json(
            '''Create a JSON with:
- action: "test"
- status: "success"
- message: "This is a test"

Return ONLY JSON, no markdown.''',
            system="You are an API. Respond ONLY with valid JSON.",
            max_tokens=500
        )
        print(f"Result: {json.dumps(json_result2, indent=2)}\n")
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_deepseek())