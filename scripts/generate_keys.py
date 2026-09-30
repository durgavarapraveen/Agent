#!/usr/bin/env python3
"""Generate cryptographically random encryption keys for AntiGravity."""

import base64
import os
import secrets
import sys
from pathlib import Path


def generate_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    env_path = project_root / ".env"

    if "--stdout" in sys.argv:
        print(generate_key())
        return

    new_key = generate_key()
    print(f"Generated ENCRYPTION_KEY: {new_key}")

    if not env_path.exists():
        print(f"\n.env not found at {env_path}")
        print("Set these in your environment:")
        print(f'  ENCRYPTION_KEY="{new_key}"')
        print(f'  ENCRYPTION_KEY_CURRENT="{new_key}"')
        return

    text = env_path.read_text(encoding="utf-8")
    insecure_values = [
        "ANTIGRAVITY_MASTER_KEY_32BYTES_LONG!",
        "CHANGE_ME_RUN_generate_keys",
    ]

    updated = False
    for insecure in insecure_values:
        if insecure in text:
            text = text.replace(insecure, new_key)
            updated = True

    if updated:
        env_path.write_text(text, encoding="utf-8")
        print(f"Updated {env_path} with new key.")
    else:
        print(f".env does not contain known insecure placeholder values.")
        print(f"To use the new key, manually set:")
        print(f'  ENCRYPTION_KEY="{new_key}"')
        print(f'  ENCRYPTION_KEY_CURRENT="{new_key}"')

    if "--rotate" in sys.argv:
        prev_key = generate_key()
        print(f"\nFor key rotation, set ENCRYPTION_KEY_PREVIOUS to your current key")
        print(f"before replacing ENCRYPTION_KEY_CURRENT with the new one.")


if __name__ == "__main__":
    main()
