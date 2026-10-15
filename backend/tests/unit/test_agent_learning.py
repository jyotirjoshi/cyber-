"""Candidate learning never changes prompt memory without an explicit review."""
import datetime as dt
import uuid

import pytest
from sqlalchemy.dialects import postgresql

from app.core.errors import ConflictError, PermissionDeniedError, ResourceNotFoundError
from app.db.enums import Role
from app.db.models.agent import AgentMemory
from app.db.models.knowledge import AgentMemoryCandidate
from app.services.context import Principal


class Session:
    def __init__(self, *results):
        self.results = list(results)
        self.added = []
        self.statements = []

    async def scalar(self, statement):
        self.statements.append(statement)
        return self.results.pop(0) if self.results else None

    def add(self, value):
        self.added.append(value)

    async def flush(self):
        pass


@pytest.fixture
def owner():
    return Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)


def candidate(owner, **overrides):
    data = {"id": uuid.uuid4(), "organization_id": owner.organization_id,
        "key": "change.window", "category": "operational",
        "content": "Production CAB is Wednesday", "status": "pending",
        "confidence": 0.9, "evidence": [{"kind": "run", "id": str(uuid.uuid4())}]}
    return AgentMemoryCandidate(**(data | overrides))


@pytest.mark.asyncio
async def test_proposal_stores_candidate_not_prompt_memory(owner):
    from app.schemas.agent_learning import MemoryCandidateCreateIn
    from app.services.agent_learning import propose_memory_candidate
    session = Session(uuid.uuid4(), None)
    row = await propose_memory_candidate(session, owner, MemoryCandidateCreateIn(
        key="change.window", content="Production CAB is Wednesday", confidence=.9,
        evidence=[{"kind": "run", "id": uuid.uuid4()}]))
    assert row.status == "pending"
    assert row.organization_id == owner.organization_id
    assert not any(isinstance(item, AgentMemory) for item in session.added)
    statement = str(session.statements[0].compile(dialect=postgresql.dialect()))
    assert "organization_id" in statement and "status" in statement


@pytest.mark.asyncio
async def test_foreign_or_unfinished_evidence_is_not_accepted(owner):
    from app.schemas.agent_learning import MemoryCandidateCreateIn
    from app.services.agent_learning import propose_memory_candidate
    session = Session(None)
    with pytest.raises(ResourceNotFoundError):
        await propose_memory_candidate(session, owner, MemoryCandidateCreateIn(
            key="change.window", content="Production CAB is Wednesday", confidence=.9,
            evidence=[{"kind": "run", "id": uuid.uuid4()}]))
    assert not session.added


@pytest.mark.asyncio
async def test_approval_promotes_edited_content_with_atomic_no_overwrite(owner):
    from app.schemas.agent_learning import MemoryCandidateApproveIn
    from app.services.agent_learning import approve_memory_candidate
    row = candidate(owner)
    memory_id = uuid.uuid4()
    session = Session(row, uuid.uuid4(), memory_id)
    approved = await approve_memory_candidate(session, owner, row.id,
        MemoryCandidateApproveIn(content="CAB is Thursday", rationale="Checked with operations"))
    assert approved.status == "approved" and approved.approved_memory_id == memory_id
    assert approved.reviewed_by_id == owner.user_id
    insert = session.statements[-1].compile(dialect=postgresql.dialect())
    assert "ON CONFLICT" in str(insert) and "DO NOTHING" in str(insert)
    assert insert.params["content"] == "CAB is Thursday"
    assert insert.params["source"] == "approved_agent"


@pytest.mark.asyncio
async def test_duplicate_memory_key_requires_explicit_manual_edit(owner):
    from app.schemas.agent_learning import MemoryCandidateApproveIn
    from app.services.agent_learning import approve_memory_candidate
    row = candidate(owner)
    with pytest.raises(ConflictError):
        await approve_memory_candidate(Session(row, uuid.uuid4(), None), owner, row.id, MemoryCandidateApproveIn())
    assert row.status == "pending"


@pytest.mark.asyncio
@pytest.mark.parametrize("overrides", [{"status": "rejected"}, {"expires_at": dt.datetime.now(dt.UTC) - dt.timedelta(days=1)}])
async def test_resolved_or_expired_candidate_cannot_be_approved(owner, overrides):
    from app.schemas.agent_learning import MemoryCandidateApproveIn
    from app.services.agent_learning import approve_memory_candidate
    row = candidate(owner, **overrides)
    session = Session(row)
    with pytest.raises(ConflictError):
        await approve_memory_candidate(session, owner, row.id, MemoryCandidateApproveIn())
    assert len(session.statements) == 1


@pytest.mark.asyncio
async def test_agent_cannot_approve_its_own_learning_even_with_owner_role(owner):
    from app.schemas.agent_learning import MemoryCandidateApproveIn
    from app.services.agent_learning import approve_memory_candidate
    agent = Principal(user_id=owner.user_id, organization_id=owner.organization_id, role=Role.OWNER, actor_type="agent")
    with pytest.raises(PermissionDeniedError):
        await approve_memory_candidate(Session(), agent, uuid.uuid4(), MemoryCandidateApproveIn())


@pytest.mark.asyncio
async def test_non_manager_cannot_review_and_rejection_creates_no_memory(owner):
    from app.schemas.agent_learning import MemoryCandidateRejectIn
    from app.services.agent_learning import reject_memory_candidate
    reader = Principal(user_id=uuid.uuid4(), organization_id=owner.organization_id, role=Role.VIEWER)
    with pytest.raises(PermissionDeniedError):
        await reject_memory_candidate(Session(), reader, uuid.uuid4(), MemoryCandidateRejectIn(rationale="Incorrect"))
    row = candidate(owner)
    session = Session(row)
    result = await reject_memory_candidate(session, owner, row.id, MemoryCandidateRejectIn(rationale="Incorrect"))
    assert result.status == "rejected"
    assert not any(isinstance(item, AgentMemory) for item in session.added)
