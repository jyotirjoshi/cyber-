from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_container_pins_google_genai_runtime_used_by_chat_and_embeddings() -> None:
    """The deployed 0.5 SDK lacks HttpOptions used by both production adapters."""
    requirement = "google-genai==2.3.0"

    assert requirement in (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert requirement in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_google_client_can_construct_with_the_pinned_sdk() -> None:
    from app.core.config import LLMSettings
    from app.llm.google_client import GoogleClient

    client = GoogleClient(
        LLMSettings(provider="google", google_api_key="test-only", default_model="gemini")
    )
    try:
        assert client.name == "google"
    finally:
        client._client.close()  # Constructor compatibility test owns this client.
