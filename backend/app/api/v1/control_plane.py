"""Unified CAASM, policy, posture, and recommendation API."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, status

from app.api.deps import DbSession, PrincipalDep
from app.schemas.control_plane import (
    AIGatewayEvaluateIn,
    AIGatewayEvaluateOut,
    DataClassificationIn,
    DataClassificationOut,
    SecurityPolicyCreateIn,
    SecurityPolicyEvaluationOut,
    SecurityPolicyOut,
    SecurityPostureOut,
    SecurityRecommendationDecisionIn,
    SecurityRecommendationOut,
    SecurityResourceOut,
    SecurityResourceUpsertIn,
)
from app.services import ai_security
from app.services import control_plane as service

router = APIRouter(prefix="/control-plane", tags=["control-plane"])


@router.post("/ai-gateway/evaluate", response_model=AIGatewayEvaluateOut)
async def evaluate_ai_gateway(
    payload: AIGatewayEvaluateIn, principal: PrincipalDep, session: DbSession
) -> AIGatewayEvaluateOut:
    result = await ai_security.evaluate_and_record(session, principal, payload)
    await session.commit()
    return result


@router.post("/data-security/classify", response_model=DataClassificationOut)
async def classify_data(
    payload: DataClassificationIn, principal: PrincipalDep, session: DbSession
) -> DataClassificationOut:
    result = await ai_security.classify_and_record(
        session, principal, payload.content, resource_key=payload.resource_key
    )
    await session.commit()
    return result


@router.get("/resources", response_model=list[SecurityResourceOut])
async def resources(
    principal: PrincipalDep,
    session: DbSession,
    kind: str | None = None,
    posture_status: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[SecurityResourceOut]:
    rows = await service.list_resources(
        session, principal, kind=kind, posture_status=posture_status, limit=limit
    )
    return [SecurityResourceOut.model_validate(row) for row in rows]


@router.post("/resources", response_model=SecurityResourceOut, status_code=status.HTTP_201_CREATED)
async def upsert_resource(
    payload: SecurityResourceUpsertIn, principal: PrincipalDep, session: DbSession
) -> SecurityResourceOut:
    row = await service.upsert_resource(session, principal, payload)
    await session.commit()
    return SecurityResourceOut.model_validate(row)


@router.get("/posture", response_model=SecurityPostureOut)
async def posture(principal: PrincipalDep, session: DbSession) -> SecurityPostureOut:
    return SecurityPostureOut.model_validate(await service.posture_summary(session, principal))


@router.get("/policies", response_model=list[SecurityPolicyOut])
async def policies(principal: PrincipalDep, session: DbSession) -> list[SecurityPolicyOut]:
    return [SecurityPolicyOut.model_validate(row) for row in await service.list_policies(session, principal)]


@router.post("/policies", response_model=SecurityPolicyOut, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: SecurityPolicyCreateIn, principal: PrincipalDep, session: DbSession
) -> SecurityPolicyOut:
    row = await service.create_policy(session, principal, payload)
    await session.commit()
    return SecurityPolicyOut.model_validate(row)


@router.post("/policies/{policy_id}/evaluate", response_model=list[SecurityPolicyEvaluationOut])
async def evaluate_policy(
    policy_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> list[SecurityPolicyEvaluationOut]:
    rows = await service.evaluate_policy(session, principal, policy_id)
    await session.commit()
    return [SecurityPolicyEvaluationOut.model_validate(row) for row in rows]


@router.get("/recommendations", response_model=list[SecurityRecommendationOut])
async def recommendations(
    principal: PrincipalDep, session: DbSession, status_filter: str | None = Query(default=None, alias="status")
) -> list[SecurityRecommendationOut]:
    rows = await service.list_recommendations(session, principal, status=status_filter)
    return [SecurityRecommendationOut.model_validate(row) for row in rows]


@router.post(
    "/recommendations/{recommendation_id}/decision", response_model=SecurityRecommendationOut
)
async def decide_recommendation(
    recommendation_id: uuid.UUID,
    payload: SecurityRecommendationDecisionIn,
    principal: PrincipalDep,
    session: DbSession,
) -> SecurityRecommendationOut:
    row = await service.decide_recommendation(session, principal, recommendation_id, payload)
    await session.commit()
    return SecurityRecommendationOut.model_validate(row)


__all__ = ["router"]
