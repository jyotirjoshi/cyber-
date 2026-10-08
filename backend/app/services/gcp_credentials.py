"""Mint a short-lived project-scoped access token from a tenant-owned service account."""

from __future__ import annotations

import datetime as dt
import json
import re

from app.core.errors import UnsafeScannerInvocationError

_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
_EMAIL = re.compile(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com")


def mint_gcp_access_token(service_account_json: str, expected_project: str) -> str:
    """Never hand the long-lived JSON key to a scanner container or archive it."""
    if not _PROJECT.fullmatch(expected_project) or len(service_account_json) > 32_768:
        raise UnsafeScannerInvocationError("Invalid GCP service-account configuration.")
    try:
        info = json.loads(service_account_json)
        if (
            not isinstance(info, dict)
            or info.get("type") != "service_account"
            or info.get("project_id") != expected_project
            or info.get("token_uri") != "https://oauth2.googleapis.com/token"
            or not isinstance(info.get("client_email"), str)
            or not _EMAIL.fullmatch(info["client_email"])
            or not isinstance(info.get("private_key"), str)
            or not info["private_key"].startswith("-----BEGIN PRIVATE KEY-----")
        ):
            raise ValueError("invalid service-account fields")

        import google.auth.transport.requests
        import requests
        from google.oauth2 import service_account

        credentials = service_account.Credentials.from_service_account_info(
            info,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        with requests.Session() as http:
            http.trust_env = False
            credentials.refresh(google.auth.transport.requests.Request(session=http))
        token = credentials.token
        expiry = credentials.expiry
        if expiry is not None and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=dt.UTC)
        if (
            not isinstance(token, str)
            or not token
            or expiry is None
            or expiry - dt.datetime.now(dt.UTC) < dt.timedelta(minutes=45)
        ):
            raise ValueError("access token expires too soon")
        return token
    except Exception:
        # Auth libraries may include sensitive response/request content in exceptions.
        raise UnsafeScannerInvocationError(
            "GCP service-account credentials could not mint a usable access token."
        ) from None
