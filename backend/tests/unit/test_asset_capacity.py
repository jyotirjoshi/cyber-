"""Inventory capacity behaviour at the discovery boundary."""

from __future__ import annotations

from app.scanners.recon_assets import DiscoveredAsset
from app.services.asset import _new_asset_count


def test_new_asset_count_does_not_charge_a_rediscovered_inventory_key() -> None:
    """A full organization can continue to rediscover assets it already owns."""
    known = DiscoveredAsset(
        name="api.example.test", asset_type="host", port=443, protocol="https"
    )
    new = DiscoveredAsset(
        name="admin.example.test", asset_type="host", port=443, protocol="https"
    )

    assert _new_asset_count([known, new], {known.key: object()}) == 1
