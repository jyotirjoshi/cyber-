"""Bounded OpenAI and Gemini embedding adapters sharing one vector contract."""
from __future__ import annotations

import math
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Protocol

from app.core.config import Settings
from app.core.errors import InvalidConfigurationError

DIMENSIONS = 1536
MAX_BATCH = 32
MODELS = {
    "openai": frozenset({"text-embedding-3-small", "text-embedding-3-large"}),
    "google": frozenset({"gemini-embedding-001"}),
}


class EmbeddingDimensionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class EmbeddingProfile:
    provider: str
    model: str

    def __post_init__(self):
        if self.model not in MODELS.get(self.provider, ()):
            raise ValueError("unsupported embedding profile")

    @property
    def key(self) -> str:
        return f"{self.provider}:{self.model}:{DIMENSIONS}:v1"


class EmbeddingProvider(Protocol):
    profile: EmbeddingProfile
    async def embed(self, texts: Sequence[str], *, query: bool = False) -> list[list[float]]: ...


def validate_vectors(vectors: Sequence[Sequence[float]], expected: int) -> list[list[float]]:
    if len(vectors) != expected:
        raise EmbeddingDimensionError("embedding count does not match inputs")
    normalized = []
    for values in vectors:
        if len(values) != DIMENSIONS:
            raise EmbeddingDimensionError("embedding provider must return 1536 dimensions")
        try:
            vector = [float(x) for x in values]
            norm = math.hypot(*vector)
        except (TypeError, ValueError, OverflowError) as exc:
            raise EmbeddingDimensionError("invalid embedding values") from exc
        if not math.isfinite(norm) or norm == 0 or not all(math.isfinite(x) for x in vector):
            raise EmbeddingDimensionError("embedding must be finite and nonzero")
        normalized.append([x / norm for x in vector])
    return normalized


def _inputs(texts: Sequence[str]) -> list[str]:
    values = list(texts)
    if not 1 <= len(values) <= MAX_BATCH:
        raise ValueError("embedding batch must contain 1 to 32 texts")
    if any(not text.strip() or len(text.encode()) > 8000 for text in values):
        raise ValueError("embedding text must contain 1 to 8000 UTF-8 bytes")
    return values


class OpenAIEmbeddingProvider:
    def __init__(self, client: Any, profile: EmbeddingProfile):
        self.client, self.profile = client, profile

    async def embed(self, texts: Sequence[str], *, query: bool = False) -> list[list[float]]:
        values = _inputs(texts)
        result = await self.client.embeddings.create(
            model=self.profile.model, input=values, dimensions=DIMENSIONS, encoding_format="float",
        )
        rows = sorted(result.data, key=lambda row: row.index)
        if [row.index for row in rows] != list(range(len(values))):
            raise EmbeddingDimensionError("embedding response indices do not match inputs")
        return validate_vectors([row.embedding for row in rows], len(values))


class GoogleEmbeddingProvider:
    def __init__(self, models: Any, profile: EmbeddingProfile):
        self.models, self.profile = models, profile

    async def embed(self, texts: Sequence[str], *, query: bool = False) -> list[list[float]]:
        values = _inputs(texts)
        result = await self.models.embed_content(
            model=self.profile.model, contents=values,
            config={"output_dimensionality": DIMENSIONS,
                    "task_type": "RETRIEVAL_QUERY" if query else "RETRIEVAL_DOCUMENT"},
        )
        return validate_vectors([row.values for row in (result.embeddings or [])], len(values))


@asynccontextmanager
async def embedding_provider(settings: Settings, profile: EmbeddingProfile) -> AsyncIterator[EmbeddingProvider]:
    """Use already tenant-resolved settings; never accept keys in model arguments."""
    if profile.provider == "openai":
        from openai import AsyncOpenAI
        key = settings.llm.openai_api_key
        if key is None or not key.get_secret_value():
            raise InvalidConfigurationError("OpenAI embedding API key is not configured")
        async with AsyncOpenAI(api_key=key.get_secret_value(), base_url=settings.llm.openai_base_url,
                               timeout=45, max_retries=0) as client:
            yield OpenAIEmbeddingProvider(client, profile)
    else:
        from google import genai
        from google.genai import types
        key = settings.llm.google_api_key
        if key is None or not key.get_secret_value():
            raise InvalidConfigurationError("Gemini embedding API key is not configured")
        client = genai.Client(api_key=key.get_secret_value(), http_options=types.HttpOptions(
            timeout=45_000, retry_options=types.HttpRetryOptions(attempts=1)))
        try:
            yield GoogleEmbeddingProvider(client.aio.models, profile)
        finally:
            await client.aio.aclose()
            client.close()
