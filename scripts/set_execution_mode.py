#!/usr/bin/env python3
import sys
import os

MODES = {
    "A": "Approach A (DeepSeek + TaskManager)",
    "B": "Approach B (Claude MCP)",
    "A_B": "Hybrid (Both, with fallback)"
}

def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/set_execution_mode.py <mode>")
        print("Available modes: A, B, A_B")
        sys.exit(1)
        
    mode = sys.argv[1].upper()
    
    if mode not in MODES:
        print(f"Error: Invalid mode '{mode}'.")
        print("Available modes: A, B, A_B")
        sys.exit(1)
        
    env_file = ".env"
    
    lines = []
    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
    found = False
    for i, line in enumerate(lines):
        if line.startswith("EXECUTION_MODE="):
            lines[i] = f"EXECUTION_MODE={mode}\n"
            found = True
            break
            
    if not found:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append(f"EXECUTION_MODE={mode}\n")
        
    with open(env_file, "w", encoding="utf-8") as f:
        f.writelines(lines)
        
    print(f"Successfully set execution mode to: {mode}")
    print(f"Mode meaning: {MODES[mode]}")
    print("Changes take effect on next run.")

if __name__ == "__main__":
    main()
