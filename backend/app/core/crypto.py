"""Envelope encryption for integration credentials at rest (SEC-001, SEC-002).

Credentials live in ``integration_credentials.ciphertext`` as a Fernet token.  The
active key encrypts; the active key plus any previous keys decrypt, so keys can be
rotated without downtime and without a data migration.

Nothing in this module ever logs plaintext, and :class:`Secret` refuses to render
itself in reprs or f-strings so a credential cannot leak into a log line, an error
message, or an LLM prompt by accident.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core.config import Settings
from app.core.errors import ConfigurationError, CynuxError


class CredentialDecryptionError(CynuxError):
    default_user_message = (
        "A stored credential could not be decrypted. It was likely encrypted with a "
        "key that is no longer configured; re-enter the credential to fix this."
    )


class Secret:
    """A string that will not appear in logs, tracebacks or LLM context.

    Call :meth:`reveal` at the exact moment the value is needed.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "Secret([REDACTED])"

    __str__ = __repr__

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        # Constant-time to avoid a timing oracle on credential comparison.
        import hmac

        return hmac.compare_digest(self._value, other._value)

    def __hash__(self) -> int:
        return hash(("cynux.Secret", self._value))


class CredentialCipher:
    """Encrypt/decrypt integration credentials."""

    def __init__(self, active_key: str, previous_keys: list[str] | None = None) -> None:
        if not active_key:
            raise ConfigurationError(
                "CYNUX_SECURITY__CREDENTIAL_ENCRYPTION_KEY is required to store "
                "integration credentials.",
                setting="CYNUX_SECURITY__CREDENTIAL_ENCRYPTION_KEY",
            )
        keys = [active_key, *(previous_keys or [])]
        try:
            self._fernet = MultiFernet([Fernet(k.encode()) for k in keys])
        except (ValueError, TypeError) as exc:
            raise ConfigurationError(
                "CYNUX_SECURITY__CREDENTIAL_ENCRYPTION_KEY is not a valid Fernet key. "
                "It must be 32 url-safe base64-encoded bytes.",
                setting="CYNUX_SECURITY__CREDENTIAL_ENCRYPTION_KEY",
            ) from exc

    def encrypt(self, plaintext: str | Secret) -> str:
        value = plaintext.reveal() if isinstance(plaintext, Secret) else plaintext
        return self._fernet.encrypt(value.encode()).decode()

    def decrypt(self, ciphertext: str) -> Secret:
        try:
            return Secret(self._fernet.decrypt(ciphertext.encode()).decode())
        except InvalidToken as exc:
            raise CredentialDecryptionError("credential decryption failed") from exc

    def rotate(self, ciphertext: str) -> str:
        """Re-encrypt an existing token under the current active key."""
        try:
            return self._fernet.rotate(ciphertext.encode()).decode()
        except InvalidToken as exc:
            raise CredentialDecryptionError("credential rotation failed") from exc


_cipher: CredentialCipher | None = None


def get_cipher(settings: Settings) -> CredentialCipher:
    global _cipher
    if _cipher is None:
        _cipher = CredentialCipher(
            settings.security.credential_encryption_key.get_secret_value(),
            [k.get_secret_value() for k in settings.security.credential_encryption_previous_keys],
        )
    return _cipher


def reset_cipher_cache() -> None:
    """Test hook."""
    global _cipher
    _cipher = None


__all__ = [
    "CredentialCipher",
    "CredentialDecryptionError",
    "Secret",
    "get_cipher",
    "reset_cipher_cache",
]
