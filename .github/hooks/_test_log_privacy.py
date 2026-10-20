"""Run privacy checks with in-memory I/O; never execute tool commands."""

# Keep these tests runnable without pytest.
# ruff: noqa: PT009, PT027

import importlib.util
import io
import json
import os
import sys
import unittest
from collections.abc import Mapping
from contextlib import ExitStack
from pathlib import Path
from types import ModuleType
from unittest.mock import mock_open, patch

ROOT = Path(__file__).resolve().parents[2]
HOOK_DIRS = tuple(directory for directory in ('.github/hooks', '.claude/hooks') if (ROOT / directory).is_dir())
SENTINEL = 'fictional_private_marker_73519'


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError('could not load hook test module')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MemoryStream(io.StringIO):
    def reconfigure(self, *, encoding: str, errors: str) -> None:
        pass


class LogPrivacyTests(unittest.TestCase):
    inspections = 0

    def test_stream_configuration(self) -> None:
        for directory in HOOK_DIRS:
            helper = load_module('stream_test', ROOT / directory / 'hook_input.py')
            buffer = io.BytesIO()
            with io.TextIOWrapper(buffer, encoding='cp932') as stream:
                helper.configure_stream(stream, errors='backslashreplace')
                stream.write('\ud800')
                stream.flush()
                self.assertEqual(stream.encoding, 'utf-8')
                self.assertEqual(buffer.getvalue(), b'\\ud800')
                helper.configure_stream(stream, errors='strict')
                self.assertEqual(stream.errors, 'strict')
            memory_stream = MemoryStream()
            helper.configure_stream(memory_stream, errors='strict')
            with self.assertRaisesRegex(TypeError, 'must support reconfigure'):
                helper.configure_stream(io.StringIO(), errors='strict')

    def inspect(
        self, directory: str, phase: str, payload: Mapping[str, object], expected: int, reason: str = '', failure: str | None = None
    ) -> tuple[str, str]:
        type(self).inspections += 1
        hook_path = ROOT / directory / f'{phase}_tool_inspect.py'
        stdin = MemoryStream(json.dumps(payload))
        stdout = MemoryStream()
        stderr = MemoryStream()
        mocked_open = mock_open()
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {'HOOK_NO_LOG': '', 'HOOK_LOG_PATH': '/fictional/audit.log'}))
            stack.enter_context(patch('sys.stdin', stdin))
            stack.enter_context(patch('sys.stdout', stdout))
            stack.enter_context(patch('sys.stderr', stderr))
            stack.enter_context(patch('builtins.open', mocked_open))
            mkdir = stack.enter_context(patch('os.makedirs'))
            for target in ('subprocess.run', 'subprocess.Popen', 'subprocess.call', 'os.system', 'socket.socket'):
                stack.enter_context(patch(target, side_effect=AssertionError('External operation forbidden')))
            if failure == 'write':
                mocked_open.side_effect = OSError(SENTINEL)
            elif failure == 'mkdir':
                mkdir.side_effect = OSError(SENTINEL)
            elif failure == 'parse':
                stack.enter_context(patch('json.load', side_effect=ValueError(SENTINEL)))
            hook = load_module('privacy_test', hook_path)
            with self.assertRaises(SystemExit) as stopped:
                hook.main()
            self.assertEqual(stopped.exception.code, expected)
        records = ''.join(call.args[0] for call in mocked_open.return_value.write.call_args_list)
        diagnostics = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(SENTINEL, records + diagnostics)
        self.assertEqual(stdout.getvalue(), '')
        self.assertNotIn('Traceback', diagnostics)
        if reason:
            self.assertIn(reason, diagnostics if expected else records)
        if failure in ('write', 'mkdir'):
            self.assertIn('write failed', diagnostics)
        return records, diagnostics

    def test_pre_privacy_and_decisions(self) -> None:
        for directory in HOOK_DIRS:
            cases = [
                ('Bash', {'command': f'git reset --hard {SENTINEL}'}, 2, 'git reset --hard'),
                ('PowerShell', {'command': f'Remove-Item -Recurse -Force C:/fictional/{SENTINEL}'}, 2, 'recursive force remove'),
                ('Bash', {'command': f'cat /fictional/{SENTINEL}/.env'}, 2, 'secret-like path'),
                ('Read', {'file_path': f'C:/fictional/{SENTINEL}/.env'}, 2, 'sensitive file access'),
                ('Edit', {'file_path': f'C:/fictional/{SENTINEL}.key'}, 2, 'sensitive file access'),
                ('Write', {'file_path': 'out.txt', 'content': 'https://example.invalid?' + f'token={SENTINEL}'}, 2, 'credential-like'),
                ('Bash', {'command': f'echo {SENTINEL}'}, 0, 'cmd:[REDACTED]'),
                ('Bash', {'command': SENTINEL}, 0, 'cmd:[REDACTED]'),
                ('Read', {'file_path': f'C:/fictional/{SENTINEL}.txt'}, 0, 'path:[REDACTED]'),
                ('Write', {'file_path': 'out.txt', 'content': SENTINEL}, 0, 'path:[REDACTED]'),
                ('Bash', {'command': f'echo {SENTINEL}' + chr(0x200B)}, 2, 'invisible Unicode'),
                (SENTINEL, {}, 0, 'ALLOWED'),
            ]
            for tool, arguments, expected, reason in cases:
                with self.subTest(directory=directory, case=reason, expected=expected):
                    self.inspect(directory, 'pre', {'tool_name': tool, 'tool_input': arguments}, expected, reason)
            with self.subTest(directory=directory, case='CLI JSON arguments'):
                if directory == '.github/hooks':
                    self.inspect(
                        directory,
                        'pre',
                        {'toolName': 'bash', 'toolArgs': json.dumps({'command': f'git reset --hard {SENTINEL}'})},
                        2,
                        'git reset --hard',
                    )

    def test_post_privacy_and_decisions(self) -> None:
        for directory in HOOK_DIRS:
            for output, expected, reason in (
                (SENTINEL, 0, 'ALLOWED'),
                (SENTINEL + chr(0x200B), 2, 'invisible Unicode'),
                ('<system>' + SENTINEL + '</system>', 2, 'potential injection'),
                ('password=' + SENTINEL, 2, 'potential password'),
            ):
                with self.subTest(directory=directory, reason=reason):
                    self.inspect(directory, 'post', {'tool_name': SENTINEL, 'tool_response': {'stdout': output}}, expected, reason)
            if directory == '.github/hooks':
                self.inspect(
                    directory, 'post', {'toolName': SENTINEL, 'toolResult': {'textResultForLlm': 'password=' + SENTINEL}}, 2, 'potential password'
                )

    def test_errors_do_not_echo_values(self) -> None:
        for directory in HOOK_DIRS:
            for phase in ('pre', 'post'):
                payload = {'tool_name': 'Bash', 'tool_input': {'command': f'echo {SENTINEL}'}, 'tool_response': {'stdout': SENTINEL}}
                for failure in ('write', 'mkdir', 'parse'):
                    expected = (2 if phase == 'pre' else 1) if failure == 'parse' else 0
                    with self.subTest(directory=directory, phase=phase, failure=failure):
                        self.inspect(directory, phase, payload, expected, failure=failure)

    def test_existing_decision_fixtures_in_memory(self) -> None:
        for directory in HOOK_DIRS:
            module_name = 'fixtures_' + directory.strip('.').replace('/', '_')
            fixtures = load_module(module_name, ROOT / directory / '_hook_fixtures.py')
            for phase in ('pre', 'post'):
                cases = getattr(fixtures, f'{phase}_cases')
                self.assertTrue(cases)
                for description, payload, flagged in cases:
                    with self.subTest(directory=directory, case=description):
                        self.inspect(directory, phase, payload, 2 if flagged else 0)


if __name__ == '__main__':
    program = unittest.main(exit=False)
    print(f'In-memory hook inspections: {LogPrivacyTests.inspections}')
    sys.exit(0 if program.result.wasSuccessful() else 1)
