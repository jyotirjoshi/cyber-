"""Bounded extraction and deterministic provenance-preserving document chunking."""

from __future__ import annotations

import hashlib
import io
import json
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass

from pypdf import PdfReader

DEFAULT_MAX_DOCUMENT_BYTES = 20 * 1024 * 1024
SUPPORTED_MIME_TYPES = frozenset(
    {"text/plain", "text/markdown", "application/pdf", "application/json",
     "application/sarif+json", "application/vnd.cyclonedx+json", "application/spdx+json"}
)
MAX_EXTRACTED_CHARACTERS = 2_000_000
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MARKDOWN_HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$")


class KnowledgeExtractionError(ValueError):
    """A safe, stable extraction failure suitable for source lifecycle state."""

    def __init__(self, error_code: str) -> None:
        self.error_code = error_code
        super().__init__(error_code)


@dataclass(frozen=True, slots=True)
class ExtractedBlock:
    text: str
    page: int | None
    section: str | None


@dataclass(frozen=True, slots=True)
class DocumentChunk:
    ordinal: int
    text: str
    token_count: int
    page: int | None
    section: str | None
    content_hash: str


def _base_mime_type(mime_type: str) -> str:
    return mime_type.partition(";")[0].strip().casefold()


def validate_upload(
    data: bytes,
    mime_type: str,
    *,
    max_bytes: int = DEFAULT_MAX_DOCUMENT_BYTES,
) -> str:
    """Validate a document before allocating parser state and return canonical MIME type."""
    resolved = _base_mime_type(mime_type)
    if resolved not in SUPPORTED_MIME_TYPES:
        raise KnowledgeExtractionError("unsupported_media_type")
    if not data:
        raise KnowledgeExtractionError("empty_document")
    if len(data) > max_bytes:
        raise KnowledgeExtractionError("document_too_large")
    return resolved


def normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n")
    normalized = normalized.replace("\u00a0", " ")
    normalized = _CONTROL_CHARACTERS.sub("", normalized)
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in normalized.split("\n")]
    compact: list[str] = []
    for line in lines:
        if line or (compact and compact[-1]):
            compact.append(line)
    return "\n".join(compact).strip()


def _section_for_text(text: str) -> str | None:
    for line in text.splitlines():
        match = _MARKDOWN_HEADING.match(line)
        if match:
            return normalize_text(match.group(1))[:500] or None
    return None


def remove_repeated_furniture(blocks: list[ExtractedBlock]) -> list[ExtractedBlock]:
    """Remove repeated first/last PDF lines while preserving page and section metadata."""
    if len(blocks) < 2:
        return blocks
    edge_counts: Counter[str] = Counter()
    for block in blocks:
        lines = [line.strip() for line in block.text.splitlines() if line.strip()]
        for line in set(lines[:1] + lines[-1:]):
            if len(line) <= 200:
                edge_counts[line] += 1
    threshold = max(2, math.ceil(len(blocks) * 0.6))
    repeated = {line for line, count in edge_counts.items() if count >= threshold}
    if not repeated:
        return blocks
    cleaned: list[ExtractedBlock] = []
    for block in blocks:
        lines = block.text.splitlines()
        # Remove furniture only at the edges, never an identical line in the body.
        if lines and lines[0].strip() in repeated:
            lines = lines[1:]
        if lines and lines[-1].strip() in repeated:
            lines = lines[:-1]
        text = normalize_text("\n".join(lines))
        if text:
            cleaned.append(ExtractedBlock(text=text, page=block.page, section=block.section))
    return cleaned


def _extract_pdf(data: bytes) -> list[ExtractedBlock]:
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise KnowledgeExtractionError("encrypted_pdf")
        if len(reader.pages) > 2000:
            raise KnowledgeExtractionError("document_too_large")
        blocks: list[ExtractedBlock] = []
        extracted_characters = 0
        for index, page in enumerate(reader.pages, start=1):
            text = normalize_text(page.extract_text() or "")
            extracted_characters += len(text)
            if extracted_characters > MAX_EXTRACTED_CHARACTERS:
                raise KnowledgeExtractionError("document_too_large")
            if text:
                blocks.append(
                    ExtractedBlock(text=text, page=index, section=_section_for_text(text))
                )
    except KnowledgeExtractionError:
        raise
    except Exception as exc:
        raise KnowledgeExtractionError("invalid_pdf") from exc
    blocks = remove_repeated_furniture(blocks)
    if not blocks:
        raise KnowledgeExtractionError("empty_document")
    return blocks


def extract_document(data: bytes, *, mime_type: str) -> list[ExtractedBlock]:
    resolved = validate_upload(data, mime_type)
    if resolved == "application/pdf":
        return _extract_pdf(data)
    try:
        text = normalize_text(data.decode("utf-8", errors="strict"))
    except UnicodeDecodeError as exc:
        raise KnowledgeExtractionError("invalid_text_encoding") from exc
    if not text:
        raise KnowledgeExtractionError("empty_document")
    if len(text) > MAX_EXTRACTED_CHARACTERS:
        raise KnowledgeExtractionError("document_too_large")
    if resolved == "application/json" or resolved.endswith("+json"):
        try:
            payload = json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise KnowledgeExtractionError("invalid_json") from exc
        blocks: list[ExtractedBlock] = []
        def visit(value, path: str, depth: int = 0):
            if depth > 30 or len(blocks) > 20_000:
                raise KnowledgeExtractionError("document_too_large")
            if isinstance(value, dict):
                for key, item in value.items():
                    visit(item, f"{path}.{key}"[:500], depth + 1)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    visit(item, f"{path}[{index}]"[:500], depth + 1)
            elif value is not None:
                blocks.append(ExtractedBlock(f"{path}: {value}", None, path))
        visit(payload, "$")
        if not blocks:
            raise KnowledgeExtractionError("empty_document")
        return blocks
    blocks = []
    section = None
    lines = []
    for line in text.splitlines():
        heading = _MARKDOWN_HEADING.match(line) if resolved == "text/markdown" else None
        if heading:
            if lines:
                blocks.append(ExtractedBlock("\n".join(lines), None, section))
            lines = []
            section = heading.group(1)[:500]
        lines.append(line)
    if lines:
        blocks.append(ExtractedBlock("\n".join(lines), None, section))
    return blocks


def chunk_document(
    blocks: list[ExtractedBlock],
    *,
    max_tokens: int = 400,
    overlap_tokens: int = 60,
) -> list[DocumentChunk]:
    """Split independently per provenance block using deterministic whitespace tokens."""
    if max_tokens < 1 or overlap_tokens < 0 or overlap_tokens >= max_tokens:
        raise ValueError("chunk overlap must be non-negative and smaller than the chunk")
    chunks: list[DocumentChunk] = []
    step = max_tokens - overlap_tokens
    for block in blocks:
        # Split pathological long words too, and cap UTF-8 bytes before provider I/O.
        # token_count is a deterministic whitespace estimate, not a provider tokenizer.
        tokens = [word[start:start + 256] for word in block.text.split()
                  for start in range(0, len(word), 256)]
        for start in range(0, len(tokens), step):
            window = tokens[start : start + max_tokens]
            if not window:
                continue
            text = " ".join(window)
            if len(text.encode()) > 8000:
                # Smaller windows keep even non-Latin / minified input below provider limits.
                return chunk_document(blocks, max_tokens=max(1, max_tokens // 2),
                                      overlap_tokens=min(overlap_tokens // 2, max(0, max_tokens // 2 - 1)))
            digest_input = f"{block.page or ''}\0{block.section or ''}\0{text}".encode()
            chunks.append(
                DocumentChunk(
                    ordinal=len(chunks),
                    text=text,
                    token_count=len(window),
                    page=block.page,
                    section=block.section,
                    content_hash=hashlib.sha256(digest_input).hexdigest(),
                )
            )
            if start + max_tokens >= len(tokens):
                break
    if not chunks:
        raise KnowledgeExtractionError("empty_document")
    return chunks


__all__ = [
    "DEFAULT_MAX_DOCUMENT_BYTES",
    "DocumentChunk",
    "ExtractedBlock",
    "KnowledgeExtractionError",
    "SUPPORTED_MIME_TYPES",
    "chunk_document",
    "extract_document",
    "normalize_text",
    "remove_repeated_furniture",
    "validate_upload",
]
