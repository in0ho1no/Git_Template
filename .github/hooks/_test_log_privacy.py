"""Run privacy checks with in-memory I/O; never execute tool commands."""
import ast
import io
import json
import os
import socket
import subprocess
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import mock_open, patch


ROOT = Path(__file__).resolve().parents[2]
SENTINEL = "fictional_private_marker_73519"


class MemoryStream(io.StringIO):
    def reconfigure(self, **kwargs):
        pass


class LogPrivacyTests(unittest.TestCase):
    inspections = 0

    def inspect(self, directory, phase, payload, expected, reason="", failure=None):
        type(self).inspections += 1
        hook_path = ROOT / directory / f"{phase}_tool_inspect.py"
        source = hook_path.read_text(encoding="utf-8")
        namespace = {"__name__": "privacy_test", "__file__": str(hook_path)}
        stdin = MemoryStream(json.dumps(payload))
        stdout = MemoryStream()
        stderr = MemoryStream()
        mocked_open = mock_open()
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {"HOOK_NO_LOG": "", "HOOK_LOG_PATH": "/fictional/audit.log"}))
            stack.enter_context(patch("sys.stdin", stdin))
            stack.enter_context(patch("sys.stdout", stdout))
            stack.enter_context(patch("sys.stderr", stderr))
            stack.enter_context(patch("builtins.open", mocked_open))
            mkdir = stack.enter_context(patch("os.makedirs"))
            for target in ("subprocess.run", "subprocess.Popen", "subprocess.call", "os.system", "socket.socket"):
                stack.enter_context(patch(target, side_effect=AssertionError("External operation forbidden")))
            if failure == "write":
                mocked_open.side_effect = OSError(SENTINEL)
            elif failure == "mkdir":
                mkdir.side_effect = OSError(SENTINEL)
            elif failure == "parse":
                stack.enter_context(patch("json.load", side_effect=ValueError(SENTINEL)))
            exec(compile(source, str(hook_path), "exec"), namespace)
            with self.assertRaises(SystemExit) as stopped:
                namespace["main"]()
            self.assertEqual(stopped.exception.code, expected)
        records = "".join(call.args[0] for call in mocked_open.return_value.write.call_args_list)
        diagnostics = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(SENTINEL, records + diagnostics)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("Traceback", diagnostics)
        if reason:
            self.assertIn(reason, diagnostics if expected else records)
        if failure in ("write", "mkdir"):
            self.assertIn("write failed", diagnostics)
        return records, diagnostics

    def test_pre_privacy_and_decisions(self):
        for directory in (".github/hooks", ".claude/hooks"):
            cases = [
                ("Bash", {"command": f"git reset --hard {SENTINEL}"}, 2, "git reset --hard"),
                ("PowerShell", {"command": f"Remove-Item -Recurse -Force C:/fictional/{SENTINEL}"}, 2, "recursive force remove"),
                ("Bash", {"command": f"cat /fictional/{SENTINEL}/.env"}, 2, "secret-like path"),
                ("Read", {"file_path": f"C:/fictional/{SENTINEL}/.env"}, 2, "sensitive file access"),
                ("Edit", {"file_path": f"C:/fictional/{SENTINEL}.key"}, 2, "sensitive file access"),
                ("Write", {"file_path": "out.txt", "content": "https://example.invalid?" + f"token={SENTINEL}"}, 2, "credential-like"),
                ("Bash", {"command": f"echo {SENTINEL}"}, 0, "cmd:[REDACTED]"),
                ("Bash", {"command": SENTINEL}, 0, "cmd:[REDACTED]"),
                ("Read", {"file_path": f"C:/fictional/{SENTINEL}.txt"}, 0, "path:[REDACTED]"),
                ("Write", {"file_path": "out.txt", "content": SENTINEL}, 0, "path:[REDACTED]"),
                ("Bash", {"command": f"echo {SENTINEL}" + chr(0x200B)}, 2, "invisible Unicode"),
                (SENTINEL, {}, 0, "ALLOWED"),
            ]
            for tool, arguments, expected, reason in cases:
                with self.subTest(directory=directory, case=reason, expected=expected):
                    self.inspect(directory, "pre", {"tool_name": tool, "tool_input": arguments}, expected, reason)
            with self.subTest(directory=directory, case="CLI JSON arguments"):
                if directory == ".github/hooks":
                    self.inspect(directory, "pre", {"toolName": "bash", "toolArgs": json.dumps({"command": f"git reset --hard {SENTINEL}"})}, 2, "git reset --hard")

    def test_post_privacy_and_decisions(self):
        for directory in (".github/hooks", ".claude/hooks"):
            for output, expected, reason in (
                (SENTINEL, 0, "ALLOWED"),
                (SENTINEL + chr(0x200B), 2, "invisible Unicode"),
                ("<system>" + SENTINEL + "</system>", 2, "potential injection"),
                ("password=" + SENTINEL, 2, "potential password"),
            ):
                with self.subTest(directory=directory, reason=reason):
                    self.inspect(directory, "post", {"tool_name": SENTINEL, "tool_response": {"stdout": output}}, expected, reason)
            if directory == ".github/hooks":
                self.inspect(directory, "post", {"toolName": SENTINEL, "toolResult": {"textResultForLlm": "password=" + SENTINEL}}, 2, "potential password")

    def test_errors_do_not_echo_values(self):
        for directory in (".github/hooks", ".claude/hooks"):
            for phase in ("pre", "post"):
                payload = {"tool_name": "Bash", "tool_input": {"command": f"echo {SENTINEL}"}, "tool_response": {"stdout": SENTINEL}}
                for failure in ("write", "mkdir", "parse"):
                    expected = (2 if phase == "pre" else 1) if failure == "parse" else 0
                    with self.subTest(directory=directory, phase=phase, failure=failure):
                        self.inspect(directory, phase, payload, expected, failure=failure)

    def test_existing_decision_fixtures_in_memory(self):
        fixture_names = {"_cred_url", "_basic_auth", "_zwsp", "_rlo", "_alm", "_lri", "_pdi", "pre_cases", "post_cases"}
        for directory in (".github/hooks", ".claude/hooks"):
            fixture_path = ROOT / directory / "_test_hook.py"
            tree = ast.parse(fixture_path.read_text(encoding="utf-8"))
            fixtures = []
            for statement in tree.body:
                if isinstance(statement, ast.Assign):
                    names = [target.id for target in statement.targets if isinstance(target, ast.Name)]
                    if names == ["ok"]:
                        break
                    if names and all(name in fixture_names for name in names):
                        fixtures.append(statement)
                elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                    function = statement.value.func
                    if (isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name)
                            and function.value.id == "pre_cases" and function.attr in {"extend", "append"}):
                        fixtures.append(statement)
            namespace = {"json": json}
            exec(compile(ast.Module(body=fixtures, type_ignores=[]), str(fixture_path), "exec"), namespace)
            for phase in ("pre", "post"):
                cases = namespace[f"{phase}_cases"]
                self.assertTrue(cases)
                for description, payload, flagged in cases:
                    with self.subTest(directory=directory, case=description):
                        self.inspect(directory, phase, payload, 2 if flagged else 0)


if __name__ == "__main__":
    program = unittest.main(exit=False)
    print(f"In-memory hook inspections: {LogPrivacyTests.inspections}")
    sys.exit(0 if program.result.wasSuccessful() else 1)