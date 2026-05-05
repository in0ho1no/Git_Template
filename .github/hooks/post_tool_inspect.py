#!/usr/bin/env python3
"""
Workspace PostToolUse hook for GitHub Copilot.
Inspects tool outputs for prompt-injection patterns and sensitive data leakage.
Exit 2 to surface a warning to the model (cannot undo the completed tool action).
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any

EXPLANATORY_CONTEXT_PATTERNS = [
    r"\bfor example\b",
    r"\bexample\b",
    r"\bquoted?\b",
    r"これは例",
    r"例です",
    r"例えば",
    r"たとえば",
    r"インジェクション",
    r"prompt[- ]?injection",
    r"検知",
    r"報告",
    r"フォーマット",
    r"指示文",
]

SECRET_PLACEHOLDER_PATTERNS = [
    r"example",
    r"sample",
    r"dummy",
    r"test(?:ing)?",
    r"fake",
    r"placeholder",
    r"changeme",
    r"default",
    r"replace(?:[_ -]?me)?",
    r"redacted",
    r"\byour[_ -]?(?:api[_-]?key|token|secret|password)\b",
    r"例です",
    r"サンプル",
]

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
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9\-_+/]{24,}['\"]?", "API key", True),
    (r"(?i)(secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9\-_+/]{20,}['\"]?", "secret/token", True),
    (r"(?i)(password|passwd)\s*[:=]\s*['\"]?[^\s'\"\\]{16,}['\"]?", "password", True),
    (r"sk-[A-Za-z0-9]{40,}",                                          "OpenAI-style key", False),
    (r"AKIA[0-9A-Z]{16}",                                             "AWS access key", False),
    (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",                   "private key", False),
    (r"(?i)anthropic[_-]api[_-]key\s*[:=]",                           "Anthropic API key", False),
    (r"(?i)aws_secret_access_key\s*[:=]",                             "AWS secret key", False),
]


def warn(reason: str) -> None:
    print(f"WARNING by post_tool_inspect.py: {reason}", file=sys.stderr)
    sys.exit(2)


def has_explanatory_context(text: str, start: int, end: int) -> bool:
    window_start = max(0, start - 80)
    window_end = min(len(text), end + 80)
    window = text[window_start:window_end]
    prefix = text[max(0, start - 10):start]
    suffix = text[end:min(len(text), end + 20)]

    if ("「" in prefix and "」" in suffix) or ('"' in prefix and '"' in suffix):
        return True

    return any(re.search(pattern, window, flags=re.IGNORECASE) for pattern in EXPLANATORY_CONTEXT_PATTERNS)


def has_secret_placeholder_context(text: str, start: int, end: int) -> bool:
    window_start = max(0, start - 80)
    window_end = min(len(text), end + 80)
    window = text[window_start:window_end]
    return any(re.search(pattern, window, flags=re.IGNORECASE) for pattern in SECRET_PLACEHOLDER_PATTERNS)


def extract_text(value: Any) -> str:
    """Recursively extract all string content from a tool_response value."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        parts = []
        seen_keys = set()
        for key in ("output", "content", "result", "text", "stdout"):
            if key not in value:
                continue
            text = extract_text(value[key])
            if text:
                parts.append(text)
            seen_keys.add(key)
        for key, val in value.items():
            if key in seen_keys:
                continue
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

    tool_name: str = data.get("tool_name", "") or ""
    output = extract_text(data.get("tool_response", {}))

    if not output:
        sys.exit(0)

    for pat, label in INJECTION_PATTERNS:
        for match in re.finditer(pat, output, flags=re.IGNORECASE):
            if has_explanatory_context(output, match.start(), match.end()):
                continue
            warn(f"potential injection in {tool_name} output [{label}]")

    for pat, label, allow_placeholder_skip in SENSITIVE_DATA_PATTERNS:
        for match in re.finditer(pat, output):
            if allow_placeholder_skip and has_secret_placeholder_context(output, match.start(), match.end()):
                continue
            warn(f"potential {label} in {tool_name} output")

    sys.exit(0)


if __name__ == "__main__":
    main()
