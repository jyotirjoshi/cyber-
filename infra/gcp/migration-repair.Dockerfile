# Repair only migration code while retaining a verified immutable runtime image.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY --chown=cynux:cynux backend/alembic /app/alembic
