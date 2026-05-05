#!/usr/bin/env python3
"""
Workspace PreToolUse hook for GitHub Copilot.
Inspects shell commands, file paths, and written content for dangerous
patterns. Exit 2 to block (stderr -> model).
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any, Iterable


SHELL_TOOL_HINTS = ("bash", "powershell", "shell", "terminal", "command")
PATH_KEY_HINTS = ("path", "file", "dir", "cwd")
CONTENT_KEYS = {
    "content",
    "text",
    "newcontent",
    "newstring",
    "replacement",
}
SENSITIVE_PATH_PATTERNS = [
    r"(^|/)\.env($|\.|/)",
    r"(^|/)\.ssh/",
    r"(^|/)\.aws/",
    r"(^|/)\.gnupg/",
    r"\.pem$",
    r"\.key$",
    r"(^|/)id_rsa($|\.pub$)",
    r"(^|/)id_ed25519($|\.pub$)",
    r"(^|/)credentials(\.json|\.yaml|\.yml)?$",
]
SECRET_PATH_PATTERN = (
    r"(\.env(\.|$|\s|/)"
    r"|/\.ssh/|/\.aws/|/\.gnupg/"
    r"|\.pem(\s|$)|\.key(\s|$)"
    r"|id_rsa(\s|$|\.pub)|id_ed25519(\s|$|\.pub)"
    r"|credentials(\.|$|\s))"
)
SECRET_URL_PATTERNS = [
    r"https?://[^\s'\"]*[?#][^\s'\"]*(token|secret|api[-_]?key|password|credential)\s*=",
    r"https?://[^\s/'\":]+:[^\s/@'\"]+@",
]
SHELL_READERS = (
    r"\b(cat|less|more|head|tail|cp|mv|grep|awk|sed|od|xxd|base64|tar|zip|"
    r"get-content|gc|type|copy-item|move-item)\b"
)
SHELL_DANGEROUS_PATTERNS = [
    (r"\brm\s+-rf?\s+(/|~|\$HOME|\*)", "rm -rf against root/home/wildcard"),
    (r"\|\s*(sh|bash|zsh)\b", "piping into a shell"),
    (r"\bgit\s+push\s+(--force|-f\b)", "git force-push"),
    (r"\bgit\s+reset\s+--hard\b", "git reset --hard"),
    (r"\bgit\s+filter-(branch|repo)\b", "git history rewrite"),
    (r"\beval\b", "use of eval"),
    (r"\bchmod\s+-?R?\s*777\b", "chmod 777"),
    (r":\(\)\s*\{.*:\|:&.*\}", "fork bomb pattern"),
    (r"\bdd\s+[^|]*\bof=/dev/", "dd writing to device"),
    (r">\s*/dev/sd[a-z]", "raw disk write"),
    (
        r"\bremove-item\b(?=[^\n\r]*\s-(recurse|r)\b)"
        r"(?=[^\n\r]*\s-(force|fo)\b)[^\n\r]*(?:[a-z]:/|/|~|\$HOME|\*)",
        "powershell recursive force remove",
    ),
    (r"\b(del|erase)\b(?=[^\n\r]*\s/s\b)(?=[^\n\r]*\s/q\b)", "cmd recursive quiet delete"),
    (r"\brmdir\b(?=[^\n\r]*\s/s\b)(?=[^\n\r]*\s/q\b)", "cmd recursive quiet directory delete"),
]


def block(reason: str) -> None:
    print(f"BLOCKED by pre_tool_inspect.py: {reason}", file=sys.stderr)
    sys.exit(2)


def normalize_path(value: str) -> str:
    return value.replace("\\", "/")


def iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from iter_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from iter_strings(nested)


def collect_keyed_strings(value: Any, key_hints: tuple[str, ...] | set[str]) -> list[str]:
    collected: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized_key = key.replace("_", "").lower()
            if isinstance(key_hints, set):
                if normalized_key in key_hints:
                    collected.extend(iter_strings(nested))
            elif any(hint in normalized_key for hint in key_hints):
                collected.extend(iter_strings(nested))
            collected.extend(collect_keyed_strings(nested, key_hints))
    elif isinstance(value, list):
        for nested in value:
            collected.extend(collect_keyed_strings(nested, key_hints))
    return collected


def looks_like_shell_tool(tool_name: str, tool_input: dict[str, Any]) -> bool:
    normalized_name = tool_name.lower()
    if any(hint in normalized_name for hint in SHELL_TOOL_HINTS):
        return True
    return bool(collect_keyed_strings(tool_input, {"command", "args"}))


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except Exception as exc:
        print(f"[pre_tool_inspect] input parse error: {exc}", file=sys.stderr)
        sys.exit(1)

    tool_name = data.get("tool_name", "") or ""
    tool_input = data.get("tool_input", {}) or {}

    if looks_like_shell_tool(tool_name, tool_input):
        shell_commands = collect_keyed_strings(tool_input, {"command"})
        if not shell_commands:
            shell_commands = list(iter_strings(tool_input))
        for command in shell_commands:
            normalized_command = normalize_path(command)
            for pattern, label in SHELL_DANGEROUS_PATTERNS:
                if re.search(pattern, normalized_command, flags=re.IGNORECASE):
                    block(f"{label}: {command!r}")
            if re.search(
                SHELL_READERS + r"[^|;&]*" + SECRET_PATH_PATTERN,
                normalized_command,
                flags=re.IGNORECASE,
            ):
                block(f"shell access to secret-like path: {command!r}")

    path_candidates = collect_keyed_strings(tool_input, PATH_KEY_HINTS)
    for path in path_candidates:
        normalized_path = normalize_path(path)
        for pattern in SENSITIVE_PATH_PATTERNS:
            if re.search(pattern, normalized_path, flags=re.IGNORECASE):
                block(f"sensitive file access: {path!r}")

    content_candidates = collect_keyed_strings(tool_input, CONTENT_KEYS)
    for content in content_candidates:
        for pattern in SECRET_URL_PATTERNS:
            if re.search(pattern, content, flags=re.IGNORECASE):
                block("suspicious URL with credential-like data in output")

    sys.exit(0)


if __name__ == "__main__":
    main()