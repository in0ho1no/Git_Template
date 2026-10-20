#!/usr/bin/env python3
"""Smoke tests for .github/hooks/pre_tool_inspect.py and post_tool_inspect.py.

This script only passes JSON strings to the hooks for regex inspection.
No actual commands are executed.
Use --inspection-only to skip filesystem-based audit log tests.
"""

import json
import os
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

from _hook_fixtures import _alm, _pdi, _zwsp, post_cases, pre_cases

os.environ['HOOK_NO_LOG'] = '1'  # Suppress audit log writes during tests
# Hook paths below are repo-root relative; resolve them from this file's location so the script runs from any cwd.
os.chdir(Path(__file__).resolve().parents[2])
HOOK_DIRS = tuple(hook_dir for hook_dir in ('.claude/hooks', '.github/hooks') if os.path.isdir(hook_dir))

PRE_HOOK = [sys.executable, '.github/hooks/pre_tool_inspect.py']
POST_HOOK = [sys.executable, '.github/hooks/post_tool_inspect.py']


def run(hook: list[str], payload: dict | bytes, extra_env: dict[str, str] | None = None) -> tuple[int, str]:
    env = os.environ.copy()
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    if extra_env:
        env.update(extra_env)
    raw_input = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode('utf-8')
    result = subprocess.run(hook, input=raw_input, capture_output=True, env=env, timeout=10)
    return result.returncode, result.stderr.decode('utf-8').strip()


def read_text(path: str) -> str:
    with open(path, encoding='utf-8') as fh:
        return fh.read()


ok = True
for desc, payload, expect_flagged in pre_cases:
    code, message = run(PRE_HOOK, payload)
    status = 'OK' if code == (2 if expect_flagged else 0) else 'FAIL'
    if status == 'FAIL':
        ok = False
    print(f'[{status}] {desc}: exit={code}' + (f' | {message}' if message else ''))

for desc, payload, expect_flagged in post_cases:
    code, message = run(POST_HOOK, payload)
    status = 'OK' if code == (2 if expect_flagged else 0) else 'FAIL'
    if status == 'FAIL':
        ok = False
    print(f'[{status}] {desc}: exit={code}' + (f' | {message}' if message else ''))

for hook_dir in HOOK_DIRS:
    for phase in ('pre', 'post'):
        hook_path = f'{hook_dir}/{phase}_tool_inspect.py'
        hook = [sys.executable, '-B', hook_path]
        for encoding in ('cp932', 'utf-8'):
            runtime_env = {'PYTHONUTF8': '0', 'PYTHONIOENCODING': f'{encoding}:surrogateescape'}
            for label, text, expected in (
                ('Japanese', '\u65e5\u672c\u8a9e', 0),
                ('invisible Unicode', '\u65e5\u672c\u8a9e' + _zwsp, 2),
            ):
                payload = {'tool_name': 'Bash', 'tool_input': {'command': f'echo {text}'}, 'tool_response': {'stdout': text}}
                code, message = run(hook, payload, runtime_env)
                passed = code == expected
                ok = ok and passed
                print(f'[{"OK" if passed else "FAIL"}] {hook_dir} {phase}: {label}, {encoding}: exit={code}')
            for raw_input in (b'{', b'\xff'):
                code, message = run(hook, raw_input, runtime_env)
                expected = 2 if phase == 'pre' else 1
                passed = code == expected and 'input parse error' in message
                ok = ok and passed
                print(f'[{"OK" if passed else "FAIL"}] {hook_dir} {phase}: invalid input {raw_input!r}, {encoding}: exit={code}')

        if phase == 'pre':
            malformed_inputs = [
                b'[]',
                b'null',
                b'1',
                b'"text"',
                b'{"tool_name":"Bash","tool_input":1}',
                b'{"tool_name":"Bash","tool_input":null}',
                b'{"tool_name":1,"tool_input":{}}',
            ]
            if hook_dir == '.claude/hooks':
                malformed_inputs.extend(
                    [
                        b'{"tool_name":"Bash","tool_input":{"command":1}}',
                        b'{"tool_name":"Read","tool_input":{"file_path":[]}}',
                        b'{"tool_name":"Write","tool_input":{"content":{}}}',
                    ]
                )
            else:
                invalid_arguments: tuple[dict[str, object], ...] = (
                    {'command': ['git', 'reset', '--hard']},
                    {'command': 1},
                    {'command': None},
                    {'command': False},
                    {'command': {}},
                    {'nested': [{'command': ['git', 'reset', '--hard']}]},
                )
                for arguments in invalid_arguments:
                    for tool_args in (arguments, json.dumps(arguments)):
                        malformed_inputs.append(json.dumps({'toolName': 'bash', 'toolArgs': tool_args}).encode('utf-8'))
            for raw_input in malformed_inputs:
                code, message = run(hook, raw_input)
                passed = code == 2 and 'Traceback' not in message
                ok = ok and passed
                print(f'[{"OK" if passed else "FAIL"}] {hook_dir}: malformed payload {raw_input!r}: exit={code}')
        else:
            for raw_input in (
                b'[]',
                b'null',
                b'1',
                b'"text"',
                b'{"tool_name":1}',
                b'{"tool_name":null}',
                b'{"tool_name":[]}',
            ):
                code, message = run(hook, raw_input)
                passed = code == 1 and 'input parse error' in message and 'Traceback' not in message
                ok = ok and passed
                print(f'[{"OK" if passed else "FAIL"}] {hook_dir}: malformed post payload {raw_input!r}: exit={code}')

        namespace = runpy.run_path(hook_path)
        encoded_records: list[bytes] = []
        mocked_open = mock_open()

        def encode_record(text: str, mocked_open: MagicMock = mocked_open, encoded_records: list[bytes] = encoded_records) -> int:
            options = mocked_open.call_args.kwargs
            encoded_records.append(text.encode(options['encoding'], errors=options.get('errors', 'strict')))
            return len(text)

        mocked_open.return_value.write.side_effect = encode_record
        with patch.dict(os.environ, {'HOOK_NO_LOG': ''}), patch('os.makedirs'), patch('builtins.open', mocked_open):
            namespace['audit_log']('PRE' if phase == 'pre' else 'POST', 'Bash', 'ALLOWED', '\ud800')
        passed = len(encoded_records) == 1 and b'\\ud800' in encoded_records[0]
        ok = ok and passed
        print(f'[{"OK" if passed else "FAIL"}] {hook_dir} {phase}: surrogate audit record (memory only)')

    namespace = runpy.run_path(f'{hook_dir}/entrypoint.py')
    project_root = Path.cwd() / 'fictional_project'
    hook_location = project_root / Path(hook_dir)
    for has_git in (False, True):
        with patch.object(Path, 'exists', lambda candidate, has_git=has_git, git_marker=project_root / '.git': has_git and candidate == git_marker):
            passed = namespace['find_repo_root'](hook_location) == project_root
        ok = ok and passed
        print(f'[{"OK" if passed else "FAIL"}] {hook_dir}: root resolution has_git={has_git} (memory only)')

if '--inspection-only' in sys.argv:
    sys.exit(0 if ok else 1)

with tempfile.TemporaryDirectory() as temp_dir:
    log_path = os.path.join(temp_dir, 'audit.log')
    code, message = run(
        PRE_HOOK,
        {'tool_name': 'run_in_terminal', 'tool_input': {'command': 'GH_TOKEN=supersecret gh api /user'}},
        {'HOOK_NO_LOG': '', 'HOOK_LOG_PATH': log_path},
    )
    log_text = read_text(log_path) if code == 0 else ''
    passed = code == 0 and 'cmd:[REDACTED]' in log_text and 'supersecret' not in log_text and 'GH_TOKEN=' not in log_text
    status = 'OK' if passed else 'FAIL'
    if status == 'FAIL':
        ok = False
    print(f'[{status}] pre: audit log summary' + (f' | {message}' if message else ''))

with tempfile.TemporaryDirectory() as temp_dir:
    log_path = os.path.join(temp_dir, 'audit.log')
    code, message = run(
        POST_HOOK,
        {'tool_name': 'read_file', 'tool_response': {'content': 'safe output should not be logged verbatim'}},
        {'HOOK_NO_LOG': '', 'HOOK_LOG_PATH': log_path},
    )
    log_text = read_text(log_path) if code == 0 else ''
    passed = code == 0 and '[POST]' in log_text and 'safe output should not be logged verbatim' not in log_text
    status = 'OK' if passed else 'FAIL'
    if status == 'FAIL':
        ok = False
    print(f'[{status}] post: audit log redaction' + (f' | {message}' if message else ''))

with tempfile.TemporaryDirectory() as temp_dir:
    blocker = os.path.join(temp_dir, 'blocked-parent')
    with open(blocker, 'w', encoding='utf-8') as fh:
        fh.write('x')
    code, message = run(
        PRE_HOOK,
        {'tool_name': 'run_in_terminal', 'tool_input': {'command': 'echo hello'}},
        {'HOOK_NO_LOG': '', 'HOOK_LOG_PATH': os.path.join(blocker, 'audit.log')},
    )
    passed = code == 0 and '[audit_log] write failed:' in message
    status = 'OK' if passed else 'FAIL'
    if status == 'FAIL':
        ok = False
    print(f'[{status}] pre: audit log write failure notice' + (f' | {message}' if message else ''))

code, message = run(
    PRE_HOOK,
    {'tool_name': 'run_in_terminal', 'tool_input': {'command': f'echo{_alm}hello'}},
)
passed = code == 2 and 'Remove suspicious content and retry.' in message
status = 'OK' if passed else 'FAIL'
if status == 'FAIL':
    ok = False
print(f'[{status}] pre: action-oriented block message' + (f' | {message}' if message else ''))

with tempfile.TemporaryDirectory() as temp_dir:
    blocker = os.path.join(temp_dir, 'blocked-parent')
    with open(blocker, 'w', encoding='utf-8') as fh:
        fh.write('x')
    code, message = run(
        POST_HOOK,
        {'tool_name': 'read_file', 'tool_response': {'content': 'safe output'}},
        {'HOOK_NO_LOG': '', 'HOOK_LOG_PATH': os.path.join(blocker, 'audit.log')},
    )
    passed = code == 0 and '[audit_log] write failed:' in message
    status = 'OK' if passed else 'FAIL'
    if status == 'FAIL':
        ok = False
    print(f'[{status}] post: audit log write failure notice' + (f' | {message}' if message else ''))

code, message = run(
    POST_HOOK,
    {'tool_name': 'read_file', 'tool_response': {'content': f'result {_pdi} value'}},
)
passed = code == 2 and 'Ignore this output and request a safer response.' in message
status = 'OK' if passed else 'FAIL'
if status == 'FAIL':
    ok = False
print(f'[{status}] post: action-oriented warning message' + (f' | {message}' if message else ''))

sys.exit(0 if ok else 1)
