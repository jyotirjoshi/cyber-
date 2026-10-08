"""Account scope checks for cloud resource identifiers in scanner evidence."""

from __future__ import annotations

import re


def resource_within_account(provider: str, account: str, resource: str) -> bool:
    """Reject an explicit foreign account while allowing IDs without an account component."""
    if provider == "aws" and resource.startswith("arn:"):
        parts = resource.split(":", 5)
        if len(parts) != 6 or parts[1] not in {"aws", "aws-us-gov", "aws-cn"}:
            return False
        return not parts[4] or parts[4] == account
    if provider == "azure":
        match = re.search(r"(?:^|/)subscriptions/([^/]+)", resource, re.I)
        return match is None or match.group(1).casefold() == account.casefold()
    if provider == "gcp":
        match = re.search(r"(?:^|/)projects/([^/]+)", resource, re.I)
        return match is None or match.group(1) in {"_", account}
    return True
