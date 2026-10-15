"""Post-quantum readiness endpoints — CBOM export and crypto asset scan."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from app.api.deps import DbSession, PrincipalDep
from app.db.enums import Permission
from app.services.postquantum import run_postquantum_scan

router = APIRouter(prefix="/postquantum", tags=["postquantum"])


class PostQuantumScanIn(BaseModel):
    assessment_id: uuid.UUID
    asset_id: uuid.UUID


class PostQuantumScanOut(BaseModel):
    total_crypto_assets: int
    vulnerable_count: int
    safe_count: int
    unclassified_count: int
    cbom: dict[str, Any]


@router.post("/scan", response_model=PostQuantumScanOut)
async def postquantum_scan(
    body: PostQuantumScanIn,
    principal: PrincipalDep,
    session: DbSession,
) -> PostQuantumScanOut:
    """Scan scanner artifacts for quantum-vulnerable algorithms and emit a CBOM."""
    principal.require(Permission.ASSESSMENT_READ)
    result = await run_postquantum_scan(
        session,
        principal,
        assessment_id=body.assessment_id,
        asset_id=body.asset_id,
    )
    await session.commit()
    return PostQuantumScanOut(**result)
