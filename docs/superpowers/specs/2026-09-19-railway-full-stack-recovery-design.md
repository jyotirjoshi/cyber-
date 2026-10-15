# Railway Full-Stack Recovery Design

## Goal

Run the Cynux API and the Next.js frontend as separate Railway services in the existing `cynux-backend` project, with production-safe service wiring and health verification.

## Architecture

The API service will use the repository root `Dockerfile`, which installs the Python project from `backend/`, runs Alembic migrations, and starts Uvicorn on Railway's assigned `PORT`. Railway must not force Nixpacks, because the Python manifest is intentionally below the repository root.

The frontend will be a dedicated Railway service built from `frontend/` using its existing Next.js standalone output. Its public API and WebSocket base URLs will be supplied as Railway build-time variables after the API domain is known. The API will receive the frontend's public origin in its CORS configuration.

## Deployment and Safety

- Preserve existing Railway secrets and database data; only add or correct service configuration.
- Use `CYNUX_` configuration and require the API's existing runtime validation to pass.
- Verify the API's `/healthz`, then verify the frontend loads and uses the deployed API origin.
- Do not configure a worker service in this recovery: scanner/worker infrastructure needs external scanner binaries, object storage, and DefectDojo credentials, which must be configured separately.

## Testing

- Build the API Docker image locally to prove the production image can install and start.
- Run the backend unit suite and frontend type check/build before deployment.
- Inspect Railway deployment logs and use public health checks after deployment.
