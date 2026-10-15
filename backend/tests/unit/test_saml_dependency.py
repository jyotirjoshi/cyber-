"""The SAML SSO implementation must use a maintained protocol library."""

from __future__ import annotations


def test_pysaml2_is_available_for_saml_assertion_validation() -> None:
    import saml2

    assert saml2.__version__.startswith("7.")


def test_saml_connection_persists_tenant_bound_idp_trust_material() -> None:
    from app.db.models.identity import SamlConnection

    columns = SamlConnection.__table__.c
    assert {"organization_id", "sp_entity_id", "idp_entity_id", "idp_sso_url", "idp_certificate_pem", "acs_url"} <= {
        column.name for column in columns
    }
