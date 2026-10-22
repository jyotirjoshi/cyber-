"""SOC case-management and detection-engineering API."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from app.api.deps import DbSession, PaginationDep, PrincipalDep
from app.schemas.common import Page
from app.schemas.soc import (
    DetectionDryRunIn,
    DetectionDryRunOut,
    DetectionEvaluationOut,
    DetectionRuleCreateIn,
    DetectionRuleOut,
    SocCaseCreateIn,
    SocCaseOut,
    SocCaseTaskCreateIn,
    SocCaseTaskOut,
    SocCaseTransitionIn,
)
from app.services import soc_operations

router = APIRouter(prefix="/control-plane/soc", tags=["soc"])


@router.get("/cases", response_model=Page[SocCaseOut])
async def list_cases(principal: PrincipalDep, session: DbSession, pagination: PaginationDep) -> Page[SocCaseOut]:
    rows, total = await soc_operations.list_cases(session, principal, limit=pagination.limit, offset=pagination.offset)
    return Page.build([SocCaseOut.model_validate(row) for row in rows], total=total, limit=pagination.limit, offset=pagination.offset)


@router.post("/cases", response_model=SocCaseOut, status_code=status.HTTP_201_CREATED)
async def create_case(payload: SocCaseCreateIn, principal: PrincipalDep, session: DbSession) -> SocCaseOut:
    row = await soc_operations.create_case(session, principal, payload)
    await session.commit()
    await session.refresh(row)
    return SocCaseOut.model_validate(row)


@router.post("/cases/{case_id}/transition", response_model=SocCaseOut)
async def transition_case(case_id: uuid.UUID, payload: SocCaseTransitionIn, principal: PrincipalDep, session: DbSession) -> SocCaseOut:
    row = await soc_operations.transition_case(session, principal, case_id, payload)
    await session.commit()
    await session.refresh(row)
    return SocCaseOut.model_validate(row)


@router.post("/cases/{case_id}/tasks", response_model=SocCaseTaskOut, status_code=status.HTTP_201_CREATED)
async def create_case_task(case_id: uuid.UUID, payload: SocCaseTaskCreateIn, principal: PrincipalDep, session: DbSession) -> SocCaseTaskOut:
    row = await soc_operations.create_case_task(session, principal, case_id, payload)
    await session.commit()
    await session.refresh(row)
    return SocCaseTaskOut.model_validate(row)


@router.get("/detection-rules", response_model=Page[DetectionRuleOut])
async def list_detection_rules(principal: PrincipalDep, session: DbSession, pagination: PaginationDep) -> Page[DetectionRuleOut]:
    rows, total = await soc_operations.list_rules(session, principal, limit=pagination.limit, offset=pagination.offset)
    return Page.build([DetectionRuleOut.model_validate(row) for row in rows], total=total, limit=pagination.limit, offset=pagination.offset)


@router.post("/detection-rules", response_model=DetectionRuleOut, status_code=status.HTTP_201_CREATED)
async def create_detection_rule(payload: DetectionRuleCreateIn, principal: PrincipalDep, session: DbSession) -> DetectionRuleOut:
    row = await soc_operations.create_rule(session, principal, payload)
    await session.commit()
    await session.refresh(row)
    return DetectionRuleOut.model_validate(row)


@router.post("/detection-rules/{rule_id}/dry-run", response_model=DetectionDryRunOut)
async def dry_run_detection_rule(rule_id: uuid.UUID, payload: DetectionDryRunIn, principal: PrincipalDep, session: DbSession) -> DetectionDryRunOut:
    rule, results = await soc_operations.dry_run_rule(session, principal, rule_id, event_ids=payload.event_ids, limit=payload.limit)
    evaluations = [
        DetectionEvaluationOut(
            event_id=event.id,
            matched=result.matched,
            matched_conditions=result.matched_conditions,
            total_conditions=result.total_conditions,
            reason_codes=list(result.reason_codes),
        )
        for event, result in results
    ]
    return DetectionDryRunOut(rule_id=rule.id, evaluated=len(evaluations), matched=sum(item.matched for item in evaluations), evaluations=evaluations)


@router.post("/detection-rules/{rule_id}/evaluate", response_model=DetectionDryRunOut)
async def evaluate_detection_rule(rule_id: uuid.UUID, payload: DetectionDryRunIn, principal: PrincipalDep, session: DbSession) -> DetectionDryRunOut:
    rule, results = await soc_operations.evaluate_rule(session, principal, rule_id, event_ids=payload.event_ids, limit=payload.limit)
    await session.commit()
    evaluations = [
        DetectionEvaluationOut(
            event_id=event.id,
            matched=result.matched,
            matched_conditions=result.matched_conditions,
            total_conditions=result.total_conditions,
            reason_codes=list(result.reason_codes),
        )
        for event, result in results
    ]
    return DetectionDryRunOut(rule_id=rule.id, evaluated=len(evaluations), matched=sum(item.matched for item in evaluations), evaluations=evaluations)
