"""Pydantic v2 wire format.

The boundary is deliberately explicit: ORM models are never returned from a route.
Every response goes through an ``*Out`` model with ``from_attributes=True``, and every
request body through an ``*In`` model with ``extra="forbid"``.

Both halves of that convention earn their keep.  ``*Out`` models are an allow-list, which
is what keeps ``users.password_hash``, ``integration_credentials.ciphertext`` and raw
scanner output from reaching a client by accident (SEC-002) -- a new column on a model
cannot leak, because it does not exist out here until someone adds it.  ``extra="forbid"``
turns a misspelled field into a 422 rather than a silently ignored instruction, which
matters most on :class:`~app.schemas.assessment.ApproveIn`: a typo'd ``asset_ids`` that
were quietly dropped would widen a scan's scope past what the operator approved.

Modules are imported for their side-effect-free definitions only; nothing here touches
the database, settings or the network, so ``app.schemas`` is safe to import from any
layer including the frontend type generator.
"""

from __future__ import annotations
