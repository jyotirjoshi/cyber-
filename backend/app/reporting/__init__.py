"""Report generation (FR-030).

Three leaf modules, in the order data flows through them:

* :mod:`app.reporting.context` turns an :class:`~app.db.models.assessment.Assessment`
  and everything hanging off it into a plain, fully-materialized ``dict``.
* :mod:`app.reporting.render` turns that dict into HTML (Jinja2, ``autoescape=True``)
  and, optionally, into PDF (WeasyPrint, in a thread).
* :mod:`app.reporting.generate` drives the whole pipeline and hands the bytes to
  object storage, recording the outcome on the ``reports`` row.

Row state -- create, ``pending`` -> ``generating`` -> ``ready`` / ``failed``, and every
read path -- lives in :mod:`app.services.report`.  The dependency runs one way only,
``app.reporting`` -> ``app.services.report``, so neither module needs a deferred import.

Import the leaf module, never this package: ``from app.reporting.render import
render_html``.
"""
