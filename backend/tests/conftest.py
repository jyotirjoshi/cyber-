"""Shared fixtures.

Two deliberate choices about how the security tests get their settings.

**No environment mutation.**  Every settings group reads ``.env`` and its own
``CYNUX_*`` prefix, so a test that used ``monkeypatch.setenv`` would depend on the
developer's local ``.env`` not defining the same variable.  Fixtures instead
construct settings objects directly with ``_env_file=None``, which makes them a
function of the test file and nothing else.

**Real objects, not mocks.**  The tests in ``tests/unit/`` that carry a SEC- or FR-
reference assert on production code paths.  A mocked ``build_sandbox`` would pass
while the sandbox was wide open, which is the one outcome those tests exist to
prevent, so nothing security-relevant is stubbed here.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from app.core.config import ScannerSettings, Settings, TargetPolicySettings

#: A valid Fernet key, generated once and hard-coded. Tests need a *well-formed* key,
#: not a secret one -- nothing encrypted here outlives the process.
TEST_FERNET_KEY = "dGVzdC1vbmx5LWtleS0zMi1ieXRlcy1sb25nLXh4eHg="
TEST_JWT_SECRET = "test-only-jwt-secret-not-used-anywhere-real"


@pytest.fixture
def scanner_settings() -> ScannerSettings:
    """Sandbox parameters at their defaults, isolated from the ambient environment."""
    return ScannerSettings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def target_policy() -> TargetPolicySettings:
    """FR-006 policy with private ranges and metadata endpoints blocked (the default)."""
    return TargetPolicySettings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def settings() -> Settings:
    """A whole-application settings object with test credentials.

    ``validate_runtime_configuration`` is *not* called: it enforces that production
    supplies real keys, which is a startup concern, not a unit-test one.
    """
    return Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def workdir(tmp_path: Path) -> Iterator[Path]:
    """A per-job scanner work directory.

    ``build_sandbox`` resolves and stats this path, so it has to genuinely exist --
    another reason the sandbox tests cannot be written against a mock.
    """
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    (job_dir / "out").mkdir()
    yield job_dir
