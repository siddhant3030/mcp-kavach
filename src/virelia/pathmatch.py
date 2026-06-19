"""Minimal JSON-path pattern matcher — zero dependencies.

Supported grammar (validated at policy load time):

    $            root (required prefix)
    .key         literal object key
    .*           any object key
    [3]          literal array index
    [*]          any array index
    ..key        recursive descent, then key (any depth of intervening segments)

Unlike a full jsonpath engine, patterns here are matched against an
already-concrete leaf path tuple produced by the engine's JSON walk —
linear time with backtracking only at ``..``.
"""

from __future__ import annotations

import re

from virelia.models import PathTuple


class PathPatternError(ValueError):
    pass


class _Wild:
    def __init__(self, label: str) -> None:
        self.label = label

    def __repr__(self) -> str:
        return self.label


WILD_KEY = _Wild("*key")
WILD_INDEX = _Wild("*index")
DESCEND = _Wild("descend")

_TOKEN = re.compile(
    r"\.\.(\*|[A-Za-z_][\w\-]*)?"  # ..  or ..key / ..*
    r"|\.(\*|[A-Za-z_][\w\-]*)"  # .key / .*
    r"|\[(\*|\d+)\]"  # [n] / [*]
)

CompiledPath = tuple


def compile_path(pattern: str) -> CompiledPath:
    if not pattern.startswith("$"):
        raise PathPatternError(f"json_path must start with '$': {pattern!r}")
    rest = pattern[1:]
    segments: list[object] = []
    pos = 0
    while pos < len(rest):
        m = _TOKEN.match(rest, pos)
        if not m:
            raise PathPatternError(
                f"invalid json_path syntax at offset {pos + 1} in {pattern!r}"
            )
        if m.group(0).startswith(".."):
            segments.append(DESCEND)
            if m.group(1):
                segments.append(WILD_KEY if m.group(1) == "*" else m.group(1))
        elif m.group(2) is not None:
            segments.append(WILD_KEY if m.group(2) == "*" else m.group(2))
        else:
            segments.append(WILD_INDEX if m.group(3) == "*" else int(m.group(3)))
        pos = m.end()
    if not segments:
        raise PathPatternError(f"json_path matches nothing: {pattern!r}")
    return tuple(segments)


def matches(compiled: CompiledPath, path: PathTuple) -> bool:
    return _match(compiled, 0, path, 0)


def _match(segs: CompiledPath, si: int, path: PathTuple, pi: int) -> bool:
    while si < len(segs):
        seg = segs[si]
        if seg is DESCEND:
            return any(
                _match(segs, si + 1, path, pi + skip)
                for skip in range(len(path) - pi + 1)
            )
        if pi >= len(path):
            return False
        p = path[pi]
        if seg is WILD_KEY:
            if not isinstance(p, str):
                return False
        elif seg is WILD_INDEX:
            if not isinstance(p, int):
                return False
        elif p != seg or isinstance(p, int) is not isinstance(seg, int):
            return False
        si += 1
        pi += 1
    return pi == len(path)


def render_path(path: PathTuple) -> str:
    """Render a concrete path tuple as a human-readable path string."""
    out = "$"
    for seg in path:
        out += f"[{seg}]" if isinstance(seg, int) else f".{seg}"
    return out
