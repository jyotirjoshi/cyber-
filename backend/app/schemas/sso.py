"""OIDC SSO connection administration contracts."""

from __future__ import annotations

import datetime as dt
import ipaddress
import uuid
from urllib.parse import urlparse

from cryptography import x509
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class OidcConnectionUpsertIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer_url: str = Field(min_length=8, max_length=2048)
    client_id: str = Field(min_length=1, max_length=512)
    client_secret: SecretStr = Field(min_length=1, max_length=4096)
    redirect_uri: str = Field(min_length=8, max_length=2048)
    allowed_email_domains: list[str] = Field(default_factory=list, max_length=100)
    is_enabled: bool = True

    @field_validator("issuer_url")
    @classmethod
    def require_secure_issuer(cls, value: str) -> str:
        parsed = urlparse(value.strip().rstrip("/"))
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("issuer_url must be a public https URL")
        if parsed.query or parsed.fragment:
            raise ValueError("issuer_url must not contain a query or fragment")
        hostname = parsed.hostname
        if not hostname or hostname.lower() in {"localhost", "localhost.localdomain"}:
            raise ValueError("issuer_url must be a public https URL")
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            pass  # Hostname is a DNS name rather than an IP literal.
        else:
            if not address.is_global:
                raise ValueError("issuer_url must be a public https URL")
        return value.strip().rstrip("/")

    @field_validator("redirect_uri")
    @classmethod
    def require_secure_callback(cls, value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("redirect_uri must be a public https URL")
        if parsed.fragment:
            raise ValueError("redirect_uri must not contain a fragment")
        return value.strip()

    @field_validator("allowed_email_domains")
    @classmethod
    def normalize_domains(cls, value: list[str]) -> list[str]:
        normalized = [domain.strip().lower().lstrip("@") for domain in value if domain.strip()]
        if len(normalized) != len(set(normalized)) or any("." not in domain for domain in normalized):
            raise ValueError("allowed_email_domains must contain unique valid domains")
        return normalized


class OidcConnectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    issuer_url: str
    client_id: str
    redirect_uri: str
    allowed_email_domains: list[str]
    is_enabled: bool
    created_at: dt.datetime
    updated_at: dt.datetime


class SamlConnectionUpsertIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sp_entity_id: str = Field(min_length=8, max_length=2048)
    idp_entity_id: str = Field(min_length=8, max_length=2048)
    idp_sso_url: str = Field(min_length=8, max_length=2048)
    idp_certificate_pem: str = Field(min_length=64, max_length=20000)
    acs_url: str = Field(min_length=8, max_length=2048)
    allowed_email_domains: list[str] = Field(default_factory=list, max_length=100)
    is_enabled: bool = True

    @field_validator("sp_entity_id", "idp_entity_id", "idp_sso_url", "acs_url")
    @classmethod
    def require_https_url(cls, value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("SAML endpoints must be public https URLs")
        if parsed.fragment:
            raise ValueError("SAML endpoints must not contain fragments")
        return value.strip()

    @field_validator("idp_certificate_pem")
    @classmethod
    def require_pem_certificate(cls, value: str) -> str:
        stripped = value.strip()
        if not (stripped.startswith("-----BEGIN CERTIFICATE-----") and stripped.endswith("-----END CERTIFICATE-----")):
            raise ValueError("idp_certificate_pem must be a PEM certificate")
        try:
            x509.load_pem_x509_certificate(stripped.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise ValueError("idp_certificate_pem must contain a valid X.509 certificate") from exc
        return stripped

    @field_validator("allowed_email_domains")
    @classmethod
    def normalize_saml_domains(cls, value: list[str]) -> list[str]:
        return OidcConnectionUpsertIn.normalize_domains(value)


class SamlConnectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    sp_entity_id: str
    idp_entity_id: str
    idp_sso_url: str
    acs_url: str
    allowed_email_domains: list[str]
    is_enabled: bool
    created_at: dt.datetime
    updated_at: dt.datetime


__all__ = [
    "OidcConnectionOut",
    "OidcConnectionUpsertIn",
    "SamlConnectionOut",
    "SamlConnectionUpsertIn",
]
