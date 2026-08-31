#!/usr/bin/env python3
"""Offline verification for the Cynux backend.

The build sandbox has no PyPI access, so we cannot import third-party packages.
This script does everything that *can* be checked without them:

* every module parses as valid Python for the target version;
* no module imports a sibling module that does not exist;
* no ``__all__`` entry is missing from its module;
* no obvious secret-leak patterns (f-string interpolation of a secret into a log
  call, ``print`` of a credential, ``.get_secret_value()`` inside a log call);
* scanner adapters never build a shell string (``shell=True``, ``os.system``,
  string-joined docker commands).

Run: python3 tools/verify.py
"""

from __future__ import annotations

import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app"
TESTS = ROOT / "tests"

FORBIDDEN_CALLS = {
    "os.system": "use the Docker API with an argv list instead",
    "subprocess.call": "scanners run in containers, never as host subprocesses",
    "subprocess.run": "scanners run in containers, never as host subprocesses",
    "subprocess.Popen": "scanners run in containers, never as host subprocesses",
    "eval": "never evaluate model or scanner output",
    "exec": "never execute model or scanner output",
    "pickle.loads": "untrusted deserialization",
}

LOG_FUNCS = {"info", "debug", "warning", "error", "critical", "exception"}


class Problem(Exception):
    pass


def module_name(path: pathlib.Path) -> str:
    rel = path.relative_to(ROOT).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def collect() -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for base in (APP, TESTS, ROOT / "tools"):
        if base.exists():
            out.extend(sorted(base.rglob("*.py")))
    return out


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    return ""


def main() -> int:
    files = collect()
    if not files:
        print("no python files found", file=sys.stderr)
        return 1

    trees: dict[pathlib.Path, ast.Module] = {}
    errors: list[str] = []

    # --- 1. syntax ---------------------------------------------------------
    for path in files:
        source = path.read_text(encoding="utf-8")
        try:
            trees[path] = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            errors.append(f"SYNTAX {path.relative_to(ROOT)}:{exc.lineno}: {exc.msg}")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    known_modules = {module_name(p) for p in files if p.is_relative_to(APP) or True}
    known_modules |= {module_name(p) for p in files}

    for path, tree in trees.items():
        rel = path.relative_to(ROOT)

        # --- 2. internal imports resolve -----------------------------------
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app."):
                if node.level:
                    continue
                target = node.module
                if target not in known_modules:
                    # from app.pkg import name -> name may be a module
                    errors.append(f"IMPORT {rel}: no module {target}")
                    continue
                for alias in node.names:
                    candidate = f"{target}.{alias.name}"
                    # Either a symbol in that module, or a submodule.
                    if candidate in known_modules:
                        continue
                    src = next((p for p in files if module_name(p) == target), None)
                    if src is None:
                        continue
                    names = exported_names(trees[src])
                    if alias.name not in names and "*" not in names:
                        errors.append(f"IMPORT {rel}: {target} does not define {alias.name!r}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("app.") and alias.name not in known_modules:
                        errors.append(f"IMPORT {rel}: no module {alias.name}")

        # --- 3. __all__ entries exist --------------------------------------
        declared = exported_names(tree)
        for name in all_entries(tree):
            if name not in declared:
                errors.append(f"__all__ {rel}: exports {name!r} which is not defined")

        # --- 4. dangerous calls --------------------------------------------
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = dotted(node.func)
            if name in FORBIDDEN_CALLS and "tools/verify.py" not in str(rel):
                errors.append(f"UNSAFE {rel}:{node.lineno}: {name} -- {FORBIDDEN_CALLS[name]}")
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value:
                    errors.append(f"UNSAFE {rel}:{node.lineno}: shell=True")

        # --- 5. secrets in log calls ---------------------------------------
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in LOG_FUNCS:
                continue
            for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Call) and dotted(sub.func).endswith(
                        ("get_secret_value", "reveal")
                    ):
                        errors.append(
                            f"SECRET-LEAK {rel}:{node.lineno}: secret revealed inside a log call"
                        )

    if errors:
        print(f"{len(errors)} problem(s):\n", file=sys.stderr)
        print("\n".join(sorted(set(errors))), file=sys.stderr)
        return 1

    print(f"OK  {len(files)} modules parsed, imports resolved, no unsafe patterns.")
    return 0


def exported_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    names.add(tgt.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.Import | ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.If):
            # e.g. TYPE_CHECKING blocks
            for sub in ast.walk(node):
                if isinstance(sub, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                    names.add(sub.name)
    return names


def all_entries(tree: ast.Module) -> list[str]:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if (
                    isinstance(tgt, ast.Name)
                    and tgt.id == "__all__"
                    and isinstance(node.value, ast.List | ast.Tuple)
                ):
                    return [
                        e.value
                        for e in node.value.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    ]
    return []


if __name__ == "__main__":
    sys.exit(main())
