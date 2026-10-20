#!/usr/bin/env python3
"""Smoke tests for pre_tool_inspect.py and post_tool_inspect.py.

This script only passes JSON strings to the hooks for regex inspection.
No actual commands are executed.
Use --inspection-only to skip filesystem-based audit log tests.
Shared encoding and root-resolution tests also run from .github/hooks/_test_hook.py.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from _hook_fixtures import _alm, _pdi, post_cases, pre_cases

os.environ['HOOK_NO_LOG'] = '1'  # Suppress audit log writes during tests
# Hook paths below are repo-root relative; resolve them from this file's location so the script runs from any cwd.
os.chdir(Path(__file__).resolve().parents[2])

PRE_HOOK = [sys.executable, '.claude/hooks/pre_tool_inspect.py']
POST_HOOK = [sys.executable, '.claude/hooks/post_tool_inspect.py']


def run(hook: list[str], payload: dict, extra_env: dict[str, str] | None = None) -> tuple[int, str]:
    env = os.environ.copy()
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    if extra_env:
        env.update(extra_env)
    raw_input = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    result = subprocess.run(hook, input=raw_input, capture_output=True, env=env, timeout=10)
    return result.returncode, result.stderr.decode('utf-8').strip()


def read_text(path: str) -> str:
    with open(path, encoding='utf-8') as fh:
        return fh.read()


ok = True
for desc, payload, expect_flagged in pre_cases:
    code, msg = run(PRE_HOOK, payload)
    status = 'OK' if code == (2 if expect_flagged else 0) else 'FAIL'
    if status == 'FAIL':
        ok = False
    print(f'[{status}] {desc}: exit={code}' + (f' | {msg}' if msg else ''))

for desc, payload, expect_flagged in post_cases:
    code, msg = run(POST_HOOK, payload)
    status = 'OK' if code == (2 if expect_flagged else 0) else 'FAIL'
    if status == 'FAIL':
        ok = False
    print(f'[{status}] {desc}: exit={code}' + (f' | {msg}' if msg else ''))

if '--inspection-only' in sys.argv:
    sys.exit(0 if ok else 1)

with tempfile.TemporaryDirectory() as temp_dir:
    log_path = os.path.join(temp_dir, 'audit.log')
    code, msg = run(
        PRE_HOOK,
        {'tool_name': 'Bash', 'tool_input': {'command': 'GH_TOKEN=supersecret gh api /user'}},
        {'HOOK_NO_LOG': '', 'HOOK_LOG_PATH': log_path},
    )
    log_text = read_text(log_path) if code == 0 else ''
    passed = code == 0 and 'cmd:[REDACTED]' in log_text and 'supersecret' not in log_text and 'GH_TOKEN=' not in log_text
    status = 'OK' if passed else 'FAIL'
    if status == 'FAIL':
        ok = False
    print(f'[{status}] pre: audit log summary' + (f' | {msg}' if msg else ''))

with tempfile.TemporaryDirectory() as temp_dir:
    log_path = os.path.join(temp_dir, 'audit.log')
    code, msg = run(
        POST_HOOK,
        {'tool_name': 'Read', 'tool_response': {'content': 'safe output should not be logged verbatim'}},
        {'HOOK_NO_LOG': '', 'HOOK_LOG_PATH': log_path},
    )
    log_text = read_text(log_path) if code == 0 else ''
    passed = code == 0 and '[POST]' in log_text and 'safe output should not be logged verbatim' not in log_text
    status = 'OK' if passed else 'FAIL'
    if status == 'FAIL':
        ok = False
    print(f'[{status}] post: audit log redaction' + (f' | {msg}' if msg else ''))

with tempfile.TemporaryDirectory() as temp_dir:
    blocker = os.path.join(temp_dir, 'blocked-parent')
    with open(blocker, 'w', encoding='utf-8') as fh:
        fh.write('x')
    code, msg = run(
        PRE_HOOK,
        {'tool_name': 'Bash', 'tool_input': {'command': 'echo hello'}},
        {'HOOK_NO_LOG': '', 'HOOK_LOG_PATH': os.path.join(blocker, 'audit.log')},
    )
    passed = code == 0 and '[audit_log] write failed:' in msg
    status = 'OK' if passed else 'FAIL'
    if status == 'FAIL':
        ok = False
    print(f'[{status}] pre: audit log write failure notice' + (f' | {msg}' if msg else ''))

code, msg = run(
    PRE_HOOK,
    {'tool_name': 'Bash', 'tool_input': {'command': f'echo{_alm}hello'}},
)
passed = code == 2 and 'Remove suspicious content and retry.' in msg
status = 'OK' if passed else 'FAIL'
if status == 'FAIL':
    ok = False
print(f'[{status}] pre: action-oriented block message' + (f' | {msg}' if msg else ''))

with tempfile.TemporaryDirectory() as temp_dir:
    blocker = os.path.join(temp_dir, 'blocked-parent')
    with open(blocker, 'w', encoding='utf-8') as fh:
        fh.write('x')
    code, msg = run(
        POST_HOOK,
        {'tool_name': 'Read', 'tool_response': {'content': 'safe output'}},
        {'HOOK_NO_LOG': '', 'HOOK_LOG_PATH': os.path.join(blocker, 'audit.log')},
    )
    passed = code == 0 and '[audit_log] write failed:' in msg
    status = 'OK' if passed else 'FAIL'
    if status == 'FAIL':
        ok = False
    print(f'[{status}] post: audit log write failure notice' + (f' | {msg}' if msg else ''))

code, msg = run(
    POST_HOOK,
    {'tool_name': 'Read', 'tool_response': {'content': f'result {_pdi} value'}},
)
passed = code == 2 and 'Ignore this output and request a safer response.' in msg
status = 'OK' if passed else 'FAIL'
if status == 'FAIL':
    ok = False
print(f'[{status}] post: action-oriented warning message' + (f' | {msg}' if msg else ''))

sys.exit(0 if ok else 1)
