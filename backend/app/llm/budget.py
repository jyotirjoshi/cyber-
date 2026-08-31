"""Context-budget enforcement (SEC-006).

The rule this module exists to enforce: *the LLM never receives raw tool output.*  Scanner
runs produce hundreds of megabytes, DefectDojo exports produce whole databases, and HTTP
response bodies produce arbitrary attacker-controlled bytes.  Passing any of that through
unbounded would blow the context window, cost a fortune, and -- worse -- carry credentials
and internal hostnames from a scanner's stderr straight into a third-party API.

Two design choices are deliberate:

*   **Truncation is always marked.**  :func:`truncate_tool_output` appends an explicit
    notice naming the label and the dropped byte count.  A model that silently receives a
    fragment will confidently reason about the missing half; one that is told it has a
    fragment says so.
*   **The budget is enforced by dropping whole middle turns, oldest first, never by
    cutting the system prompt or the newest turn.**  The system prompt carries the SEC-005
    and FR-024 guardrails, so trimming it would remove the safety instructions precisely
    when the context is most crowded.

Character counts are used as the proxy for tokens throughout.  A real tokenizer differs per
provider and per model version, and this is a *safety ceiling*: being conservative and
provider-independent matters more than being exact.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

from app.llm.base import LLMMessage

#: Rough characters-per-token across the providers Cynux supports for English prose and
#: JSON. Deliberately low so the estimate over-counts tokens rather than under-counting.
CHARS_PER_TOKEN = 3.6

TRUNCATION_NOTICE = (
    "\n\n[... {dropped} characters of {label} output omitted. This is a TRUNCATED "
    "fragment: {kept} of {total} characters are shown. Do not draw conclusions about "
    "the omitted portion, and say so if the answer depends on it. ...]"
)


def estimate_tokens(text: str) -> int:
    """Conservative token estimate from character count."""
    if not text:
        return 0
    return max(1, math.ceil(len(text) / CHARS_PER_TOKEN))


def estimate_messages_tokens(messages: Sequence[LLMMessage]) -> int:
    #: ~4 tokens of per-message framing overhead, matching what the provider APIs add
    #: for role delimiters.
    return sum(estimate_tokens(m.content) + 4 for m in messages)


def truncate_tool_output(text: str, *, limit: int, label: str) -> tuple[str, bool]:
    """Clamp one tool's output to ``limit`` characters.

    Keeps the head *and* the tail: scanner tools put the summary at the end (Nmap's run
    statistics, Nuclei's counts) while the detail is at the front, so a head-only cut
    routinely discards the most useful line in the file. Returns ``(text, was_truncated)``.
    """
    if limit <= 0:
        raise ValueError("limit must be positive")
    total = len(text)
    if total <= limit:
        return text, False

    notice_budget = len(
        TRUNCATION_NOTICE.format(dropped=total, label=label, kept=limit, total=total)
    )
    usable = max(limit - notice_budget, limit // 2)
    head_len = (usable * 2) // 3
    tail_len = usable - head_len

    head = text[:head_len]
    tail = text[total - tail_len :] if tail_len > 0 else ""
    kept = len(head) + len(tail)
    notice = TRUNCATION_NOTICE.format(dropped=total - kept, label=label, kept=kept, total=total)
    return f"{head}{notice}\n{tail}", True


def enforce_prompt_budget(messages: Sequence[LLMMessage], *, limit: int) -> Sequence[LLMMessage]:
    """Fit a prompt inside ``limit`` characters.

    Order of sacrifice: oldest non-system turns first, then -- only if the system prompt
    plus the final turn still do not fit -- the final turn's *content* is truncated with a
    marker. The system prompt is never touched; see the module docstring.
    """
    if limit <= 0:
        raise ValueError("limit must be positive")

    total = sum(m.char_count for m in messages)
    if total <= limit:
        return messages

    system = [m for m in messages if m.role == "system"]
    conversation = [m for m in messages if m.role != "system"]
    system_chars = sum(m.char_count for m in system)

    kept: list[LLMMessage] = []
    remaining = limit - system_chars
    #: Walk newest-first so the most recent context survives, then restore order.
    for message in reversed(conversation):
        if message.char_count <= remaining:
            kept.append(message)
            remaining -= message.char_count
        elif not kept:
            #: The newest turn alone exceeds the budget. Truncate it rather than send a
            #: prompt with no conversation at all.
            text, _ = truncate_tool_output(
                message.content, limit=max(remaining, 2000), label="conversation"
            )
            kept.append(LLMMessage(role=message.role, content=text))
            remaining = 0
        else:
            #: Older turns are dropped silently: the rolling context summary on the agent
            #: session is what preserves them, and a marker per dropped turn would itself
            #: consume the budget we are trying to reclaim.
            continue
    kept.reverse()

    dropped = len(conversation) - len(kept)
    if dropped > 0:
        marker = LLMMessage(
            role="user",
            content=(
                f"[{dropped} earlier turn(s) omitted to fit the context budget. "
                "Refer to the conversation summary above for their content.]"
            ),
        )
        kept.insert(0, marker)

    return [*system, *kept]


def summarize_for_prompt(items: Sequence[str], *, limit: int, label: str) -> str:
    """Render a list of records into a bounded block.

    Used where the alternative is serializing an entire result set -- the asset inventory,
    a findings page. Stops at the budget and states how many records were not included, so
    the model can say "of the 40 assets shown" instead of implying it saw all 400.
    """
    lines: list[str] = []
    used = 0
    for index, item in enumerate(items):
        line = f"{index + 1}. {item}"
        if used + len(line) + 1 > limit:
            omitted = len(items) - index
            lines.append(f"[{omitted} further {label} omitted for length.]")
            break
        lines.append(line)
        used += len(line) + 1
    return "\n".join(lines)


__all__ = [
    "CHARS_PER_TOKEN",
    "TRUNCATION_NOTICE",
    "enforce_prompt_budget",
    "estimate_messages_tokens",
    "estimate_tokens",
    "summarize_for_prompt",
    "truncate_tool_output",
]
