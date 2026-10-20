"""Normalize hook arguments without executing commands or applying patches."""

from __future__ import annotations

import json
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class _ReconfigurableStream(Protocol):
    def reconfigure(self, *, encoding: str, errors: str) -> None: ...


def configure_stream(stream: object, *, errors: str) -> None:
    """Configure UTF-8 on real or in-memory hook streams."""
    if not isinstance(stream, _ReconfigurableStream):
        raise TypeError('hook stream must support reconfigure')
    stream.reconfigure(encoding='utf-8', errors=errors)


def normalize_tool_input(tool: str, value: Any) -> dict[str, Any]:
    """Normalize JSON arguments and extract patch paths and additions."""
    tool_name = tool.rsplit('.', 1)[-1]
    is_patch = tool_name == 'apply_patch' or (tool_name == 'Edit' and isinstance(value, str) and value.lstrip().startswith('*** Begin Patch'))
    if isinstance(value, str):
        if is_patch and value.lstrip().startswith('*** Begin Patch'):
            value = {'input': value}
        else:
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError('tool arguments must contain valid JSON') from exc
    if not isinstance(value, dict):
        raise ValueError('tool arguments must be a JSON object')
    if not is_patch:
        return value

    keys = [key for key in ('input', 'patch') if key in value]
    if len(keys) != 1 or not isinstance(value[keys[0]], str):
        raise ValueError('apply_patch requires one string input or patch argument')
    paths, content = inspect_patch(value[keys[0]])
    return {**value, 'patch_paths': paths, 'patch_content': content}


def inspect_patch(patch: str) -> tuple[list[str], str]:
    """Validate patch structure without applying any file operations."""
    lines = patch.strip().splitlines()
    if len(lines) < 3 or lines[0] != '*** Begin Patch' or lines[-1] != '*** End Patch':
        raise ValueError('invalid apply_patch envelope')
    paths: list[str] = []
    additions: list[str] = []
    operation = ''
    for line in lines[1:-1]:
        for prefix, kind in (
            ('*** Add File: ', 'add'),
            ('*** Update File: ', 'update'),
            ('*** Delete File: ', 'delete'),
            ('*** Move to: ', 'move'),
        ):
            if line.startswith(prefix):
                path = line[len(prefix) :].strip()
                if not path or (kind == 'move' and operation != 'update'):
                    raise ValueError('invalid apply_patch path header')
                paths.append(path)
                if kind != 'move':
                    operation = kind
                break
        else:
            if operation == 'update' and (line == '@@' or line.startswith('@@ ') or line == '*** End of File'):
                continue
            if operation in ('add', 'update') and line.startswith('+'):
                additions.append(line[1:])
            elif operation == 'update' and line.startswith((' ', '-')):
                continue
            else:
                raise ValueError('invalid apply_patch inspection line')
    if not paths:
        raise ValueError('apply_patch requires a file header')
    return paths, '\n'.join(additions)
