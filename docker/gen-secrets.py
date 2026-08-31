#!/usr/bin/env python
"""Regenerate the change-me secrets in a Cynux .env file, in place.

Operator tooling for `make secrets` (not part of the app package). Generates
fresh high-entropy values for every secret that ships with a placeholder in
.env.example and rewrites those lines in .env, preserving everything else the
operator has set (notably the LLM API key). Secret values are never printed.

The Fernet credential-encryption key is produced as url-safe base64 of 32 random
bytes (the Fernet key format) so this script has no dependency on `cryptography`
being installed on the host.

Usage: python docker/gen-secrets.py [path-to-env]   (default: ./.env)
"""

from __future__ import annotations

import base64
import os
import re
import secrets
import sys
from collections.abc import Callable

# Keys we own and always regenerate. Anything else in .env is left untouched.
GENERATORS: dict[str, Callable[[], str]] = {
    "CYNUX_SECURITY__JWT_SECRET": lambda: secrets.token_hex(32),
    "CYNUX_SECURITY__CREDENTIAL_ENCRYPTION_KEY": lambda: base64.urlsafe_b64encode(
        os.urandom(32)
    ).decode(),
    "CYNUX_DB__PASSWORD": lambda: secrets.token_hex(16),
    "CYNUX_STORAGE__SECRET_ACCESS_KEY": lambda: secrets.token_hex(16),
    "DEFECTDOJO_DB_PASSWORD": lambda: secrets.token_hex(16),
    "DEFECTDOJO_ADMIN_PASSWORD": lambda: secrets.token_hex(16),
    "DEFECTDOJO_SECRET_KEY": lambda: secrets.token_hex(32),
    "DEFECTDOJO_CREDENTIAL_AES_256_KEY": lambda: secrets.token_hex(32),
}


def main() -> int:
    env_path = sys.argv[1] if len(sys.argv) > 1 else ".env"
    try:
        src = open(env_path, encoding="utf-8").read()
    except FileNotFoundError:
        print(f"{env_path} not found — run 'make env' first", file=sys.stderr)
        return 1

    for key, generate in GENERATORS.items():
        line = f"{key}={generate()}"
        pattern = re.compile(rf"^{re.escape(key)}=.*$", re.MULTILINE)
        src = pattern.sub(line, src) if pattern.search(src) else f"{src.rstrip()}\n{line}\n"

    with open(env_path, "w", encoding="utf-8") as fh:
        fh.write(src)
    print(f"regenerated {len(GENERATORS)} secrets in {env_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
