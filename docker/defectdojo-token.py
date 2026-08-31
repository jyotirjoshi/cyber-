#!/usr/bin/env python
"""Mint a DefectDojo API token and write it into a Cynux .env file.

Operator tooling for `make defectdojo-token` (not part of the app package).
DefectDojo only issues an API token once its stack is up and the admin user has
been created, so this cannot be baked into .env ahead of time. This script logs
in with the admin credentials already present in .env, exchanges them for the
long-lived API token, and writes it to CYNUX_DEFECTDOJO__API_TOKEN.

The token is a bearer credential: it is written to .env but never printed.

Usage: python docker/defectdojo-token.py [path-to-env]   (default: ./.env)
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


def read_env(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in open(path, encoding="utf-8"):
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def main() -> int:
    env_path = sys.argv[1] if len(sys.argv) > 1 else ".env"
    try:
        env = read_env(env_path)
    except FileNotFoundError:
        print(f"{env_path} not found — run 'make env' first", file=sys.stderr)
        return 1

    port = env.get("DEFECTDOJO_PORT", "8080")
    user = env.get("DEFECTDOJO_ADMIN_USER", "admin")
    password = env.get("DEFECTDOJO_ADMIN_PASSWORD", "")
    if not password:
        print("DEFECTDOJO_ADMIN_PASSWORD is empty in .env", file=sys.stderr)
        return 1

    url = f"http://localhost:{port}/api/v2/api-token-auth/"
    body = urllib.parse.urlencode({"username": user, "password": password}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=20) as resp:
            token = json.load(resp)["token"]
    except (urllib.error.URLError, KeyError, TimeoutError) as exc:
        print(
            f"could not get a token from DefectDojo at {url} ({type(exc).__name__}). "
            "Is 'make up-defectdojo' running and initialised?",
            file=sys.stderr,
        )
        return 1

    src = open(env_path, encoding="utf-8").read()
    line = f"CYNUX_DEFECTDOJO__API_TOKEN={token}"
    pattern = re.compile(r"^CYNUX_DEFECTDOJO__API_TOKEN=.*$", re.MULTILINE)
    src = pattern.sub(line, src) if pattern.search(src) else f"{src.rstrip()}\n{line}\n"
    with open(env_path, "w", encoding="utf-8") as fh:
        fh.write(src)

    print("wrote CYNUX_DEFECTDOJO__API_TOKEN to .env — run 'make restart' to pick it up")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
