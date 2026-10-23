from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.core.security import hash_password
from app.schemas.auth import LoginIn
from app.services import auth


@pytest.mark.asyncio
async def test_login_accepts_the_password_used_to_create_the_hash(monkeypatch):
    password = "Acceptance-Password-2026!"
    user = SimpleNamespace(password_hash=hash_password(password))
    monkeypatch.setattr(auth, "_load_user_by_email", AsyncMock(return_value=user))
    monkeypatch.setattr(auth, "_lockout_remaining", lambda *args, **kwargs: 0)

    class Verified(Exception):
        pass

    def reached_post_password_check(value):
        assert value is user
        raise Verified

    monkeypatch.setattr(auth, "_assert_active", reached_post_password_check)
    with pytest.raises(Verified):
        await auth.login(
            AsyncMock(),
            LoginIn(email="acceptance@example.com", password=password),
            settings=SimpleNamespace(),
        )
