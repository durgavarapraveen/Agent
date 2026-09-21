#!/usr/bin/env bash
# Relaunch a DEEP scan of Juice Shop to a canonical loop log for the
# self-improving coverage loop. Run via the Bash tool with run_in_background:true.
# Arg 1: absolute log path to write.
set -u
ROOT="C:/Users/durga/Desktop/Projects/outputs"
LOG="${1:?log path required}"
cd "$ROOT" || exit 1
: > "$LOG"
PYTHONIOENCODING=utf-8 .venv/Scripts/python.exe -u main.py \
  --target "https://preview.owasp-juice.shop/#/" --tier DEEP --auto-approve >> "$LOG" 2>&1
echo "scan exited rc=$?" >> "$LOG"
