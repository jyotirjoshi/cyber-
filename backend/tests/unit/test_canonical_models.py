"""The canonical ledger must persist tenant, asset and source identity."""

from sqlalchemy import UniqueConstraint

from app.db.models.canonical import CanonicalFinding, FindingHistory, FindingObservation


def test_canonical_finding_cannot_exist_without_tenant_asset_or_fingerprint() -> None:
    table = CanonicalFinding.__table__
    assert not table.c.organization_id.nullable
    assert not table.c.asset_id.nullable
    assert not table.c.fingerprint.nullable
    assert not table.c.risk_score.nullable
    assert not table.c.risk_factors.nullable
    assert any(
        isinstance(constraint, UniqueConstraint)
        and {column.name for column in constraint.columns} == {"organization_id", "fingerprint"}
        for constraint in table.constraints
    )


def test_observation_retains_unique_provider_record_and_history_is_tenant_scoped() -> None:
    table = FindingObservation.__table__
    assert not table.c.canonical_finding_id.nullable
    assert not table.c.external_id.nullable
    assert any(
        isinstance(constraint, UniqueConstraint)
        and {column.name for column in constraint.columns}
        == {"organization_id", "provider", "external_id", "cve_id"}
        for constraint in table.constraints
    )
    assert not FindingHistory.__table__.c.organization_id.nullable
    assert not FindingHistory.__table__.c.canonical_finding_id.nullable
