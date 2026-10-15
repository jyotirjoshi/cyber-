"""Small, side-effect-free CODEOWNERS matcher for remediation routing."""

from __future__ import annotations

from fnmatch import fnmatchcase


def owners_for_path(source: str, path: str) -> tuple[str, ...]:
    """Return owners from the last CODEOWNERS pattern matching ``path``."""
    normalized = path.lstrip("/")
    matched: tuple[str, ...] = ()
    for raw_line in source.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        pattern, owners = fields[0].lstrip("/"), tuple(fields[1:])
        matches = normalized.startswith(pattern) if pattern.endswith("/") else fnmatchcase(normalized, pattern)
        if matches:
            matched = owners
    return matched


__all__ = ["owners_for_path"]
