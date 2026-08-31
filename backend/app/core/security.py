"""Password hashing and JWT issuance/validation (FR-001).

Access tokens are short-lived and carry the caller's organization and role so the
API can enforce tenant isolation without a database round-trip on every request.
Refresh tokens are opaque-by-convention: they carry a ``jti`` that is checked
against a Redis deny list, so logout and password change genuinely revoke sessions
rather than waiting for expiry.
"""

from __future__ import annotations

import datetime as dt
import secrets
import uuid
from dataclasses import dataclass
from typing import Any, Literal

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import Settings
from app.core.errors import AuthenticationError, InvalidConfigurationError

TokenType = Literal["access", "refresh", "password_reset"]

_hasher = PasswordHasher(time_cost=3, memory_cost=65_536, parallelism=4)

ISSUER = "cynux"


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def validate_password_strength(password: str, settings: Settings) -> None:
    """Length-first policy. Composition rules are deliberately light: NIST SP 800-63B
    recommends length over character-class gymnastics."""
    min_len = settings.security.min_password_length
    if len(password) < min_len:
        raise InvalidConfigurationError(
            user_message=f"Choose a password of at least {min_len} characters."
        )
    if len(password) > 1024:
        raise InvalidConfigurationError(
            user_message="Choose a password shorter than 1024 characters."
        )
    if password.lower() in _COMMON_PASSWORDS:
        raise InvalidConfigurationError(
            user_message="That password appears in known breach lists. Choose another."
        )


_COMMON_PASSWORDS = frozenset(
    {
        "password",
        "password1",
        "password123",
        "123456789012",
        "qwertyuiop12",
        "administrator",
        "letmein12345",
        "changeme1234",
        "welcome12345",
        "cynuxpassword",
        "securitypassword",
    }
)


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TokenClaims:
    subject: uuid.UUID
    token_type: TokenType
    jti: str
    organization_id: uuid.UUID | None
    role: str | None
    expires_at: dt.datetime
    raw: dict[str, Any]


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def create_token(
    settings: Settings,
    *,
    subject: uuid.UUID,
    token_type: TokenType,
    organization_id: uuid.UUID | None = None,
    role: str | None = None,
    ttl: dt.timedelta | None = None,
    extra: dict[str, Any] | None = None,
) -> tuple[str, TokenClaims]:
    if ttl is None:
        ttl = {
            "access": dt.timedelta(minutes=settings.security.access_token_ttl_minutes),
            "refresh": dt.timedelta(days=settings.security.refresh_token_ttl_days),
            "password_reset": dt.timedelta(minutes=settings.security.password_reset_ttl_minutes),
        }[token_type]

    issued = _now()
    expires = issued + ttl
    jti = secrets.token_urlsafe(24)
    payload: dict[str, Any] = {
        "iss": ISSUER,
        "sub": str(subject),
        "typ": token_type,
        "jti": jti,
        "iat": int(issued.timestamp()),
        "nbf": int(issued.timestamp()),
        "exp": int(expires.timestamp()),
        **(extra or {}),
    }
    if organization_id is not None:
        payload["org"] = str(organization_id)
    if role is not None:
        payload["role"] = role

    token = jwt.encode(
        payload,
        settings.security.jwt_secret.get_secret_value(),
        algorithm=settings.security.jwt_algorithm,
    )
    return token, TokenClaims(
        subject=subject,
        token_type=token_type,
        jti=jti,
        organization_id=organization_id,
        role=role,
        expires_at=expires,
        raw=payload,
    )


def decode_token(settings: Settings, token: str, *, expect: TokenType) -> TokenClaims:
    """Validate signature, expiry, issuer and token type.

    Checking ``typ`` matters: without it a refresh token would be accepted as an
    access token, silently extending privilege lifetime far beyond 30 minutes.
    """
    try:
        payload = jwt.decode(
            token,
            settings.security.jwt_secret.get_secret_value(),
            algorithms=[settings.security.jwt_algorithm],
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "jti", "typ"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError(
            "token expired", user_message="Your session expired. Sign in again."
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError("invalid token") from exc

    if payload.get("typ") != expect:
        raise AuthenticationError(f"expected {expect} token, got {payload.get('typ')!r}")

    try:
        subject = uuid.UUID(payload["sub"])
        org = uuid.UUID(payload["org"]) if payload.get("org") else None
    except (ValueError, TypeError, KeyError) as exc:
        raise AuthenticationError("malformed token subject") from exc

    return TokenClaims(
        subject=subject,
        token_type=expect,
        jti=payload["jti"],
        organization_id=org,
        role=payload.get("role"),
        expires_at=dt.datetime.fromtimestamp(payload["exp"], tz=dt.UTC),
        raw=payload,
    )


def generate_api_key() -> tuple[str, str]:
    """Return ``(plaintext, hash)`` for a machine credential.

    The plaintext is shown once and never stored.
    """
    plaintext = f"cynux_{secrets.token_urlsafe(32)}"
    return plaintext, hash_password(plaintext)


__all__ = [
    "TokenClaims",
    "TokenType",
    "create_token",
    "decode_token",
    "generate_api_key",
    "hash_password",
    "needs_rehash",
    "validate_password_strength",
    "verify_password",
]
