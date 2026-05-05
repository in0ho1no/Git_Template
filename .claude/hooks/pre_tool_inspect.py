#!/usr/bin/env python3
"""
Claude Code PreToolUse hook.
Inspects Bash commands and file paths for dangerous patterns and
prompt-injection-style content. Exit 2 to block (stderr -> Claude).
"""
from __future__ import annotations

import json
import re
import sys


def block(reason: str) -> None:
    print(f"BLOCKED by pre_tool_inspect.py: {reason}", file=sys.stderr)
    sys.exit(2)


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except Exception as e:
        # Don't block on hook input failure; surface non-blocking error.
        print(f"[pre_tool_inspect] input parse error: {e}", file=sys.stderr)
        sys.exit(1)

    tool: str = data.get("tool_name", "")
    inp: dict = data.get("tool_input", {}) or {}

    # ---- Bash command checks --------------------------------------------
    if tool == "Bash":
        cmd: str = inp.get("command", "") or ""

        dangerous = [
            (r"\brm\s+-rf?\s+(/|~|\$HOME|\*)", "rm -rf against root/home/wildcard"),
            (r"\|\s*(sh|bash|zsh)\b",          "piping into a shell"),
            (r"\bgit\s+push\s+(--force|-f\b)", "git force-push"),
            (r"\bgit\s+reset\s+--hard\b",      "git reset --hard"),
            (r"\bgit\s+filter-(branch|repo)\b","git history rewrite"),
            (r"\beval\b",                      "use of eval"),
            (r"\bchmod\s+-?R?\s*777\b",        "chmod 777"),
            (r":\(\)\s*\{.*:\|:&.*\}",         "fork bomb pattern"),
            (r"\bdd\s+[^|]*\bof=/dev/",        "dd writing to device"),
            (r">\s*/dev/sd[a-z]",              "raw disk write"),
        ]
        for pat, label in dangerous:
            if re.search(pat, cmd):
                block(f"{label}: {cmd!r}")

        # Bash-level reads of secrets that bypass Read() deny rules.
        secret_path = (
            r"(\.env(\.|$|\s|/)"
            r"|/\.ssh/|/\.aws/|/\.gnupg/"
            r"|\.pem(\s|$)|\.key(\s|$)"
            r"|id_rsa(\s|$|\.pub)|id_ed25519(\s|$|\.pub)"
            r"|credentials(\.|$|\s))"
        )
        readers = r"\b(cat|less|more|head|tail|cp|mv|grep|awk|sed|od|xxd|base64|tar|zip)\b"
        if re.search(readers + r"[^|;&]*" + secret_path, cmd):
            block(f"shell access to secret-like path: {cmd!r}")

    # ---- File-path checks (defense in depth for Read/Edit/Write) --------
    if tool in ("Read", "Edit", "Write"):
        path: str = inp.get("file_path") or inp.get("path") or ""
        sensitive = [
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
        for pat in sensitive:
            if re.search(pat, path):
                block(f"sensitive file access: {path!r}")

    # ---- Content checks for Write/Edit (exfiltration patterns) ----------
    if tool in ("Write", "Edit"):
        content = (
            inp.get("content")
            or inp.get("new_string")
            or inp.get("new_content")
            or ""
        )
        # URL with credential-looking query params being embedded in code.
        if re.search(
            r"https?://[^\s'\"]+\?[^\s'\"]*=[^\s'\"]*"
            r"(token|secret|api[-_]?key|password|credential)",
            content,
            flags=re.IGNORECASE,
        ):
            block("suspicious URL with credential-like query parameter in output")

    sys.exit(0)


if __name__ == "__main__":
    main()
