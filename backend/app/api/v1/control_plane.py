"""Unified CAASM, policy, posture, and recommendation API."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, status

from app.api.deps import DbSession, PrincipalDep, RedisDep, SettingsDep
from app.integrations import control_enforcement
from app.schemas.assurance import (
    AgentRunAssuranceCreateIn,
    AgentRunAssuranceFinalizeIn,
    AgentRunAssuranceOut,
    AIAccessEdgeCreateIn,
    AIAccessEdgeOut,
    AIAccessGraphOut,
    AIAccessGraphQueryIn,
    AIRuntimeDecisionOut,
    AIRuntimeEvaluateIn,
    AIToolAuthorizationOut,
    AIToolCallAuthorizeIn,
    AIToolManifestCreateIn,
    AIToolManifestDecisionIn,
    AIToolManifestOut,
    DataSecurityAssessmentCreateIn,
    DataSecurityAssessmentOut,
    EnforcementTransactionCreateIn,
    EnforcementTransactionOut,
    EnforcementTransactionTransitionIn,
    MonteCarloSimulationCreateIn,
    OCSFEventCreateIn,
    OpenAIChatCompletionIn,
    OpenAIChatCompletionOut,
    OSCALExportCreateIn,
    OSCALExportOut,
    RiskSimulationTrialOut,
    ThreatResponseActionCreateIn,
    ThreatResponseActionOut,
    ValidationRecipeCreateIn,
    ValidationRecipeOut,
    ValidationRecipeVerifyIn,
)
from app.schemas.control_plane import (
    AIGatewayEvaluateIn,
    AIGatewayEvaluateOut,
    CanaryInteractionIn,
    CanaryInteractionOut,
    DataClassificationIn,
    DataClassificationOut,
    DeceptionCanaryCreateIn,
    DeceptionCanaryOut,
    ExperienceSummaryOut,
    RiskSimulationCreateIn,
    RiskSimulationOut,
    SecurityEventIn,
    SecurityEventOut,
    SecurityPolicyCreateIn,
    SecurityPolicyEvaluationOut,
    SecurityPolicyOut,
    SecurityPostureOut,
    SecurityRecommendationDecisionIn,
    SecurityRecommendationOut,
    SecurityResourceOut,
    SecurityResourceUpsertIn,
    ThreatStoryOut,
)
from app.services import (
    ai_runtime,
    ai_security,
    assurance_reporting,
    assurance_transactions,
    assurance_work,
    security_operations,
)
from app.services import control_plane as service

router = APIRouter(prefix="/control-plane", tags=["control-plane"])


@router.get("/assurance-summary")
async def get_assurance_summary(
    principal: PrincipalDep,
    session: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, object]:
    return await assurance_reporting.assurance_summary(session, principal, limit=limit)


@router.post("/ai-runtime/evaluate", response_model=AIRuntimeDecisionOut)
async def evaluate_ai_runtime(
    payload: AIRuntimeEvaluateIn, principal: PrincipalDep, session: DbSession
) -> AIRuntimeDecisionOut:
    decision, _ = await ai_runtime.evaluate_and_record(session, principal, payload)
    await session.commit()
    return AIRuntimeDecisionOut(
        decision=decision.decision,
        reason_codes=list(decision.reason_codes),
        prompt_digest=decision.prompt_digest,
        input_tokens_estimate=decision.input_tokens_estimate,
        requested_output_tokens=decision.requested_output_tokens,
        retention_mode=decision.retention_mode,
    )


@router.post(
    "/ai-runtime/v1/chat/completions",
    response_model=OpenAIChatCompletionOut,
)
async def proxy_ai_chat_completion(
    payload: OpenAIChatCompletionIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> OpenAIChatCompletionOut:
    result = await ai_runtime.proxy_chat_completion(
        session,
        principal,
        payload,
        settings=settings,
    )
    await session.commit()
    return OpenAIChatCompletionOut.model_validate(result)


@router.post(
    "/ai-runtime/manifests",
    response_model=AIToolManifestOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_ai_tool_manifest(
    payload: AIToolManifestCreateIn, principal: PrincipalDep, session: DbSession
) -> AIToolManifestOut:
    row = await ai_runtime.register_tool_manifest(session, principal, payload)
    await session.commit()
    return AIToolManifestOut.model_validate(row)


@router.post("/ai-runtime/manifests/{manifest_id}/decision", response_model=AIToolManifestOut)
async def decide_ai_tool_manifest(
    manifest_id: uuid.UUID,
    payload: AIToolManifestDecisionIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AIToolManifestOut:
    row = await ai_runtime.decide_tool_manifest(
        session,
        principal,
        manifest_id,
        approved=payload.approved,
        expected_schema_digest=payload.expected_schema_digest,
    )
    await session.commit()
    return AIToolManifestOut.model_validate(row)


@router.post("/ai-runtime/tool-authorizations", response_model=AIToolAuthorizationOut)
async def authorize_ai_tool_call(
    payload: AIToolCallAuthorizeIn, principal: PrincipalDep, session: DbSession
) -> AIToolAuthorizationOut:
    result = await ai_runtime.authorize_persisted_tool_call(
        session,
        principal,
        payload.manifest_id,
        arguments=payload.arguments,
        expected_manifest_digest=payload.expected_manifest_digest,
        approval_scope_digest=payload.approval_scope_digest,
        delegation_expires_at=payload.delegation_expires_at,
    )
    return AIToolAuthorizationOut(
        allowed=result.allowed,
        manifest_digest=result.manifest_digest,
        argument_digest=result.argument_digest,
        approval_scope_digest=result.approval_scope_digest,
        authorized_at=result.authorized_at,
    )


@router.post(
    "/ai-runtime/access-edges",
    response_model=AIAccessEdgeOut,
    status_code=status.HTTP_201_CREATED,
)
async def upsert_ai_access_edge(
    payload: AIAccessEdgeCreateIn, principal: PrincipalDep, session: DbSession
) -> AIAccessEdgeOut:
    row = await ai_runtime.upsert_access_edge(session, principal, payload)
    await session.commit()
    return AIAccessEdgeOut.model_validate(row)


@router.post("/ai-runtime/access-graph/query", response_model=AIAccessGraphOut)
async def query_ai_access_graph(
    payload: AIAccessGraphQueryIn, principal: PrincipalDep, session: DbSession
) -> AIAccessGraphOut:
    result = await ai_runtime.query_access_graph(
        session,
        principal,
        source_resource_id=payload.source_resource_id,
        target_resource_id=payload.target_resource_id,
        max_depth=payload.max_depth,
    )
    return AIAccessGraphOut.model_validate(result)


@router.post(
    "/agent-assurance",
    response_model=AgentRunAssuranceOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_agent_assurance(
    payload: AgentRunAssuranceCreateIn, principal: PrincipalDep, session: DbSession
) -> AgentRunAssuranceOut:
    row = await assurance_work.create_agent_assurance(session, principal, payload)
    await session.commit()
    return AgentRunAssuranceOut.model_validate(row)


@router.post(
    "/agent-assurance/{assurance_id}/finalize", response_model=AgentRunAssuranceOut
)
async def finalize_agent_assurance(
    assurance_id: uuid.UUID,
    payload: AgentRunAssuranceFinalizeIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AgentRunAssuranceOut:
    row = await assurance_work.finalize_agent_assurance(
        session, principal, assurance_id, payload
    )
    await session.commit()
    return AgentRunAssuranceOut.model_validate(row)


@router.post(
    "/validation-recipes",
    response_model=ValidationRecipeOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_validation_recipe(
    payload: ValidationRecipeCreateIn, principal: PrincipalDep, session: DbSession
) -> ValidationRecipeOut:
    row = await assurance_work.create_validation_recipe(session, principal, payload)
    await session.commit()
    return ValidationRecipeOut.model_validate(row)


@router.post(
    "/validation-recipes/{recipe_id}/verify", response_model=ValidationRecipeOut
)
async def verify_validation_recipe(
    recipe_id: uuid.UUID,
    payload: ValidationRecipeVerifyIn,
    principal: PrincipalDep,
    session: DbSession,
) -> ValidationRecipeOut:
    row = await assurance_work.verify_persisted_validation_recipe(
        session, principal, recipe_id, payload
    )
    await session.commit()
    return ValidationRecipeOut.model_validate(row)


@router.post(
    "/data-security/assessments",
    response_model=DataSecurityAssessmentOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_data_security_assessment(
    payload: DataSecurityAssessmentCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> DataSecurityAssessmentOut:
    row = await security_operations.create_data_security_assessment(
        session, principal, payload
    )
    await session.commit()
    return DataSecurityAssessmentOut.model_validate(row)


@router.post(
    "/soc/ocsf-events",
    response_model=SecurityEventOut,
    status_code=status.HTTP_201_CREATED,
)
async def ingest_ocsf_event(
    payload: OCSFEventCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> SecurityEventOut:
    row = await security_operations.ingest_ocsf_event(
        session, principal, payload, source="ocsf_api"
    )
    await session.commit()
    return SecurityEventOut.model_validate(row)


@router.post(
    "/soc/response-actions",
    response_model=ThreatResponseActionOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_threat_response_action(
    payload: ThreatResponseActionCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> ThreatResponseActionOut:
    row = await security_operations.create_threat_response_action(
        session, principal, payload
    )
    await session.commit()
    return ThreatResponseActionOut.model_validate(row)


@router.post(
    "/risk/trials",
    response_model=RiskSimulationTrialOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_risk_trial(
    payload: MonteCarloSimulationCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> RiskSimulationTrialOut:
    row = await assurance_reporting.run_persisted_risk_trial(session, principal, payload)
    await session.commit()
    return RiskSimulationTrialOut.model_validate(row)


@router.post(
    "/compliance/oscal-exports",
    response_model=OSCALExportOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_oscal_export(
    payload: OSCALExportCreateIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> OSCALExportOut:
    configured = settings.security.assurance_signing_secret.get_secret_value()
    signing_secret = (configured or settings.security.jwt_secret.get_secret_value()).encode()
    signing_key_id = "assurance-v1" if configured else "jwt-fallback-v1"
    row, package = await assurance_reporting.export_workspace_oscal(
        session,
        principal,
        payload,
        signing_secret=signing_secret,
        signing_key_id=signing_key_id,
    )
    await session.commit()
    return OSCALExportOut(
        package_id=row.id,
        package_key=row.package_key,
        content_digest=row.content_digest,
        signature=row.signature,
        signing_key_id=row.signing_key_id,
        manifest=row.manifest,
        document=package["document"],
    )


@router.get("/transactions", response_model=list[EnforcementTransactionOut])
async def transactions(
    principal: PrincipalDep,
    session: DbSession,
    status_filter: str | None = Query(default=None, alias="status"),
) -> list[EnforcementTransactionOut]:
    rows = await assurance_transactions.list_transactions(
        session, principal, status=status_filter
    )
    return [EnforcementTransactionOut.model_validate(row) for row in rows]


@router.post(
    "/transactions",
    response_model=EnforcementTransactionOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_transaction(
    payload: EnforcementTransactionCreateIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> EnforcementTransactionOut:
    row = await assurance_transactions.prepare_transaction(
        session,
        principal,
        payload.recommendation_id,
        settings=settings,
        redis=redis,
        observation_seconds=payload.observation_seconds,
    )
    await session.commit()
    return EnforcementTransactionOut.model_validate(row)


@router.post(
    "/transactions/{transaction_id}/transition",
    response_model=EnforcementTransactionOut,
)
async def transition_transaction(
    transaction_id: uuid.UUID,
    payload: EnforcementTransactionTransitionIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> EnforcementTransactionOut:
    row = await assurance_transactions.transition_transaction(
        session,
        principal,
        transaction_id,
        action=payload.action,
        settings=settings,
        redis=redis,
        approval_id=payload.approval_id,
        expected_diff_digest=payload.expected_diff_digest,
        verification=payload.verification,
    )
    await session.commit()
    return EnforcementTransactionOut.model_validate(row)


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


@router.get("/events", response_model=list[SecurityEventOut])
async def events(
    principal: PrincipalDep,
    session: DbSession,
    category: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[SecurityEventOut]:
    rows = await service.list_events(session, principal, category=category, limit=limit)
    return [SecurityEventOut.model_validate(row) for row in rows]


@router.post("/events", response_model=SecurityEventOut, status_code=status.HTTP_201_CREATED)
async def ingest_event(
    payload: SecurityEventIn, principal: PrincipalDep, session: DbSession
) -> SecurityEventOut:
    row = await service.ingest_event(session, principal, payload)
    await session.commit()
    return SecurityEventOut.model_validate(row)


@router.get("/experience", response_model=ExperienceSummaryOut)
async def experience(principal: PrincipalDep, session: DbSession) -> ExperienceSummaryOut:
    return ExperienceSummaryOut.model_validate(await service.experience_summary(session, principal))


@router.get("/threat-stories", response_model=list[ThreatStoryOut])
async def threat_stories(
    principal: PrincipalDep,
    session: DbSession,
    status_filter: str | None = Query(default=None, alias="status"),
) -> list[ThreatStoryOut]:
    rows = await service.list_threat_stories(session, principal, status=status_filter)
    return [ThreatStoryOut.model_validate(row) for row in rows]


@router.get("/canaries", response_model=list[DeceptionCanaryOut])
async def canaries(principal: PrincipalDep, session: DbSession) -> list[DeceptionCanaryOut]:
    return [
        DeceptionCanaryOut.model_validate(row)
        for row in await service.list_canaries(session, principal)
    ]


@router.post("/canaries", response_model=DeceptionCanaryOut, status_code=status.HTTP_201_CREATED)
async def create_canary(
    payload: DeceptionCanaryCreateIn, principal: PrincipalDep, session: DbSession
) -> DeceptionCanaryOut:
    row = await service.create_canary(session, principal, payload)
    await session.commit()
    return DeceptionCanaryOut.model_validate(row)


@router.post(
    "/canaries/{canary_id}/interactions",
    response_model=CanaryInteractionOut,
    status_code=status.HTTP_201_CREATED,
)
async def record_canary_interaction(
    canary_id: uuid.UUID,
    payload: CanaryInteractionIn,
    principal: PrincipalDep,
    session: DbSession,
) -> CanaryInteractionOut:
    row = await service.record_canary_interaction(
        session, principal, canary_id, payload
    )
    await session.commit()
    return CanaryInteractionOut.model_validate(row)


@router.get("/risk-simulations", response_model=list[RiskSimulationOut])
async def risk_simulations(
    principal: PrincipalDep, session: DbSession
) -> list[RiskSimulationOut]:
    return [
        RiskSimulationOut.model_validate(row)
        for row in await service.list_risk_simulations(session, principal)
    ]


@router.post(
    "/risk-simulations",
    response_model=RiskSimulationOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_risk_simulation(
    payload: RiskSimulationCreateIn, principal: PrincipalDep, session: DbSession
) -> RiskSimulationOut:
    row = await service.create_risk_simulation(session, principal, payload)
    await session.commit()
    return RiskSimulationOut.model_validate(row)


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
    settings: SettingsDep,
    redis: RedisDep,
) -> SecurityRecommendationOut:
    if payload.decision == "apply":
        row = await control_enforcement.apply_recommendation(
            session,
            principal,
            recommendation_id,
            settings=settings,
            redis=redis,
            dry_run=False,
        )
    else:
        row = await service.decide_recommendation(session, principal, recommendation_id, payload)
    await session.commit()
    return SecurityRecommendationOut.model_validate(row)


@router.post(
    "/recommendations/{recommendation_id}/preview", response_model=SecurityRecommendationOut
)
async def preview_recommendation(
    recommendation_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> SecurityRecommendationOut:
    row = await control_enforcement.apply_recommendation(
        session,
        principal,
        recommendation_id,
        settings=settings,
        redis=redis,
        dry_run=True,
    )
    await session.commit()
    return SecurityRecommendationOut.model_validate(row)


@router.post("/connectors/zscaler/sync", response_model=dict[str, int])
async def sync_zscaler(
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> dict[str, int]:
    count = await control_enforcement.sync_zscaler_inventory(
        session, principal, settings=settings, redis=redis
    )
    await session.commit()
    return {"resources_reconciled": count}


__all__ = ["router"]
