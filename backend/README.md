## HKERS Backend

Overview of structure and how to run/deploy.

### Project Layout
- `cmd/server/` – application entrypoint (`main.go`, `db.go`).
- `config/` – configuration loading.
- `internal/app/` – router and middleware wiring.
- `internal/core/` – domain services (auth, user) and service container.
- `internal/http/` – handlers, routes, middleware, responses, docs.
- `internal/db/` – sqlc queries, generated DB code, schema and seeds.
- `deploy/` – Dockerfile and docker-compose for local/prod-like runtime.
- `scripts/` – helper scripts (e.g., `generate-secret.sh`).
- `.example.env` – sample environment variables (copy to `.env` or inject).

### Prerequisites
- Go 1.23+
- Docker + Docker Compose (for local infra)
- Auth0 credentials (domain, client ID/secret, callback URL)
- PostgreSQL and Redis (compose provides both)

### Local Setup (Compose)
1) Copy env: `cp .example.env .env` and fill in values.  
   - Generate `SESSION_SECRET` with `./scripts/generate-secret.sh`.
2) Start stack: `docker compose -f deploy/docker-compose.yml up --build`.
3) App listens on `http://localhost:${SERVER_PORT:-3000}`; health at `/health`.

### Local Run (without Compose)
1) Export env vars (from `.example.env`) so the app can reach your Postgres/Redis.  
2) Run: `go run ./cmd/server`.

### Deployment Notes
- Build container: `docker build -f deploy/Dockerfile -t hkers-backend .`
- Provide env at runtime (no defaults for secrets): `SESSION_SECRET`, `AUTH0_*`, `POSTGRES_*`, `REDIS_*`, `GIN_MODE=release`.
- Ensure Redis is network-restricted and requires `REDIS_PASSWORD`; Postgres likewise.
- TLS/HTTPS should be terminated by your ingress/proxy; keep `Secure` cookies in release.

### Request Flow (overview)
- Client → Gin router (`internal/app/server.go`) → route groups (`internal/http/routes/*`).
- Router invokes handlers (`internal/http/handlers/*`), which:
  - read request/session, validate/auth (middleware in `internal/http/middleware`),
  - call services (`internal/core/*`) for business logic.
- Services use sqlc-generated data access (`internal/db/generated`) via `core.Container`.
- Responses are serialized via `internal/http/response`.
- Docs/swagger served via `internal/http/docs`; health via `internal/http/handlers/health`.

