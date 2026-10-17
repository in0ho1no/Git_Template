"""Check argument compatibility through the real entrypoints, without tool execution."""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HOOK_DIRS = tuple(
    hook_dir for hook_dir in (".github/hooks", ".claude/hooks")
    if (ROOT / hook_dir).is_dir()
)


def make_patch(path="src\\fictional.txt", content="safe", operation="Update File"):
    body = f"*** {operation}: {path}\n"
    if operation == "Update File":
        body += "@@\n-old\n"
    if operation != "Delete File":
        body += "+" + content + "\n"
    return "*** Begin Patch\n" + body + "*** End Patch\n"


class HookInputTests(unittest.TestCase):
    inspections = 0

    def inspect(self, directory, phase, payload, expected):
        type(self).inspections += 1
        env = os.environ.copy()
        env.update({
            "HOOK_NO_LOG": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "CLAUDE_PROJECT_DIR": str(ROOT),
        })
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(ROOT / directory / "entrypoint.py"), phase],
            input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=ROOT.parent, env=env, timeout=10,
        )
        diagnostic = result.stderr.decode("utf-8")
        self.assertEqual(result.returncode, expected, diagnostic)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn("Traceback", diagnostic)
        return diagnostic

    def test_patch_argument_forms_and_inspection(self):
        cases = [
            ("safe update", make_patch(), 0),
            ("safe add", make_patch(operation="Add File"), 0),
            ("safe delete", make_patch(operation="Delete File"), 0),
            ("Japanese", make_patch(content="\u65e5\u672c\u8a9e"), 0),
            ("env update", make_patch(path="fictional\\.env"), 2),
            ("key add", make_patch(path="fictional\\sample.key", operation="Add File"), 2),
            ("secret delete", make_patch(path="fictional\\id_rsa", operation="Delete File"), 2),
            ("secret move", make_patch().replace("@@", "*** Move to: fictional\\.env\n@@"), 2),
            ("invisible path", make_patch(path="src\\a" + chr(0x200B) + ".txt"), 2),
            ("invisible addition", make_patch(content="a" + chr(0x202E) + "b"), 2),
            ("credential URL", make_patch(content="https://example.invalid?" + "token=fictional"), 2),
            ("removed invisible", make_patch().replace("-old", "-old" + chr(0x200B)), 0),
            ("removed URL", make_patch().replace("-old", "-https://example.invalid?" + "token=fictional"), 0),
            ("header-like addition", make_patch(content="*** Move to: fictional\\.env"), 0),
        ]
        for directory in HOOK_DIRS:
            for label, patch, expected in cases:
                with self.subTest(directory=directory, case=label, form="SDK converted Edit"):
                    self.inspect(directory, "pre", {"tool_name": "Edit", "tool_input": patch}, expected)
                for form, args in (
                    ("raw", patch),
                    ("input object", {"input": patch}),
                    ("patch object", {"patch": patch}),
                    ("JSON string", json.dumps({"input": patch})),
                ):
                    for dialect in ("claude", "copilot"):
                        payload = (
                            {"tool_name": "apply_patch", "tool_input": args}
                            if dialect == "claude" else
                            {"toolName": "apply_patch", "toolArgs": args}
                        )
                        with self.subTest(directory=directory, case=label, form=form, dialect=dialect):
                            self.inspect(directory, "pre", payload, expected)

    def test_invalid_inputs_stay_blocked(self):
        for directory in HOOK_DIRS:
            for tool, args in [
                ("view", "{"), ("view", "null"), ("view", "[]"), ("view", None),
                ("Edit", "{"), ("Edit", "not a patch"), ("Edit", "[]"),
                ("Edit", "*** Begin Patch\n*** End Patch\n"),
                ("Edit", make_patch().replace("+safe", "unrecognized")),
                ("apply_patch", {"input": 1}),
                ("apply_patch", {"input": make_patch(), "patch": make_patch()}),
                ("apply_patch", {}),
                ("apply_patch", "*** Begin Patch\n*** End Patch\n"),
                ("apply_patch", "*** Begin Patch\n*** Update File: \n*** End Patch\n"),
                ("apply_patch", make_patch().replace("+safe", "unrecognized")),
                ("apply_patch", make_patch().replace("*** End Patch", "")),
            ]:
                with self.subTest(directory=directory, tool=tool, args=args):
                    self.inspect(directory, "pre", {"toolName": tool, "toolArgs": args}, 2)

    def test_serialized_claude_arguments(self):
        if ".claude/hooks" not in HOOK_DIRS:
            self.skipTest("Claude hooks are not present")
        for tool, args, expected in [
            ("Bash", {"command": "echo safe"}, 0),
            ("Bash", {"command": "git reset --hard"}, 2),
            ("Read", {"file_path": "fictional\\.env"}, 2),
            ("Write", {"file_path": "fictional.txt", "content": "safe"}, 0),
            ("Write", {"file_path": "fictional.txt", "content": chr(0x200B)}, 2),
            ("Edit", {"file_path": "fictional.txt", "new_string": "safe"}, 0),
            ("Edit", {"file_path": "fictional\\.env", "new_string": "safe"}, 2),
            ("Edit", {"file_path": "fictional.txt", "new_string": chr(0x200B)}, 2),
            ("powershell", {"command": "git reset --hard"}, 2),
            ("functions.powershell", {"command": "echo safe"}, 0),
            ("view", {"path": "fictional\\.env"}, 2),
            ("create_file", {"filePath": "fictional.txt", "content": chr(0x200B)}, 2),
        ]:
            with self.subTest(tool=tool, expected=expected):
                self.inspect(".claude/hooks", "pre", {
                    "tool_name": tool, "tool_input": json.dumps(args),
                }, expected)

    def test_patch_content_cannot_be_shadowed(self):
        for directory in HOOK_DIRS:
            with self.subTest(directory=directory):
                self.inspect(directory, "pre", {
                    "tool_name": "apply_patch",
                    "tool_input": {"input": make_patch(content=chr(0x200B)), "content": "safe"},
                }, 2)

    def test_post_copilot_response_forms(self):
        for directory in HOOK_DIRS:
            for key in ("tool_response", "toolResult", "tool_result"):
                for text, expected in [("safe", 0), ("safe" + chr(0x200B), 2)]:
                    with self.subTest(directory=directory, key=key, expected=expected):
                        self.inspect(directory, "post", {
                            "toolName": "view", key: {"textResultForLlm": text},
                        }, expected)


if __name__ == "__main__":
    program = unittest.main(exit=False)
    print(f"Entrypoint inspections: {HookInputTests.inspections}")
    sys.exit(0 if program.result.wasSuccessful() else 1)
