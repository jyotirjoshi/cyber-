# Cynux backend image — one image, three roles (api, worker, migrate).
#   api:     uvicorn --factory app.api.app:create_app
#   worker:  python -m app.worker
#   migrate: alembic upgrade head
#
# The build context is the repository root (see docker-compose.yml), so paths
# below are `backend/...`.

FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Runtime shared libraries for WeasyPrint (PDF report rendering, FR-030) plus a
# base font so generated PDFs are not blank. These are runtime libs, not build
# toolchains — every Python dependency ships a manylinux wheel, so no compiler
# is needed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libfontconfig1 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libffi8 \
        fonts-dejavu-core \
        fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependency + package install. pyproject.toml pins every version; installing the
# project pulls them in. app/ must be present because setuptools discovers it.
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini ./alembic.ini
COPY backend/tools ./tools
RUN pip install .

# Non-root by default (api, migrate). The worker service overrides `user:` to
# root in compose because it needs the mounted Docker socket.
RUN useradd --create-home --uid 1000 cynux && chown -R cynux:cynux /app
USER cynux

EXPOSE 8000

CMD ["uvicorn", "--factory", "app.api.app:create_app", "--host", "0.0.0.0", "--port", "8000"]
