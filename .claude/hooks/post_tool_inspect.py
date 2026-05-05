#!/usr/bin/env python3
"""
Claude Code PostToolUse hook.
Inspects tool outputs for prompt-injection patterns and sensitive data leakage.
Exit 2 to surface a warning to Claude (cannot undo the completed tool action).
"""
from __future__ import annotations

import json
import re
import sys

INJECTION_PATTERNS = [
    (r"ignore\s+(previous|above|prior)\s+instructions?",               "instruction override"),
    (r"上記の指示は?無視",                                               "instruction override (ja)"),
    (r"disregard\s+your\s+(previous|prior|system)\s+(instructions?|prompt)", "system prompt override"),
    (r"you\s+are\s+now\s+(?:a\s+)?(?:different|new)\s+(?:AI|assistant|bot)", "persona hijack"),
    (r"<\s*/?system\s*>",                                              "system tag injection"),
    (r"\[INST\]|\[/?SYS\]",                                           "model-specific injection tag"),
    (r"###\s*(system|instruction)\s*:",                                "markdown instruction override"),
    (r"----\s*(new\s+)?instructions?\s*----",                          "instruction separator"),
]

SENSITIVE_DATA_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{20,}", "API key"),
    (r"(?i)(secret|token|password|passwd)\s*[:=]\s*['\"]?[A-Za-z0-9\-_+/]{8,}['\"]?", "secret/token"),
    (r"sk-[A-Za-z0-9]{20,}",                                          "OpenAI-style key"),
    (r"AKIA[0-9A-Z]{16}",                                             "AWS access key"),
    (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",                   "private key"),
    (r"(?i)anthropic[_-]api[_-]key\s*[:=]",                           "Anthropic API key"),
    (r"(?i)aws_secret_access_key\s*[:=]",                             "AWS secret key"),
]


def warn(reason: str) -> None:
    print(f"WARNING by post_tool_inspect.py: {reason}", file=sys.stderr)
    sys.exit(2)


def extract_text(value: object) -> str:
    """Recursively extract all string content from a tool_response value."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("output", "content", "result", "text", "stdout"):
            val = value.get(key, "")
            if isinstance(val, str) and val:
                return val
        parts = []
        for val in value.values():
            text = extract_text(val)
            if text:
                parts.append(text)
        return "\n".join(parts)
    if isinstance(value, list):
        return "\n".join(extract_text(item) for item in value)
    return ""


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except Exception as e:
        print(f"[post_tool_inspect] input parse error: {e}", file=sys.stderr)
        sys.exit(1)

    tool: str = data.get("tool_name", "") or ""
    output = extract_text(data.get("tool_response", {}))

    if not output:
        sys.exit(0)

    for pat, label in INJECTION_PATTERNS:
        if re.search(pat, output, flags=re.IGNORECASE):
            warn(f"potential injection in {tool} output [{label}]")

    for pat, label in SENSITIVE_DATA_PATTERNS:
        if re.search(pat, output):
            warn(f"potential {label} in {tool} output")

    sys.exit(0)


if __name__ == "__main__":
    main()
