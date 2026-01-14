# NEAR AI Chat API

Rust backend that proxies OpenAI requests while tracking conversations in PostgreSQL.

## Local development setup (macOS + Linux)

### Prerequisites

- Rust toolchain `1.90.0` (see `rust-toolchain.toml`)
- PostgreSQL 16 (or Docker to run it)
- Optional (frontend build): `pnpm`, `git`

### Install dependencies

macOS (Homebrew):
```bash
brew install postgresql@16
brew services start postgresql@16
```

Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install postgresql
sudo systemctl enable --now postgresql
```

### Configure environment

```bash
cp env.example .env
```

Edit `.env` with your values.

#### Required environment variables

| Variable | Description | Example |
|----------|-------------|---------|
| `OPENAI_BASE_URL` | Cloud API endpoint (must include `/v1`) | `https://cloud-api.near.ai/v1` |
| `OPENAI_API_KEY` | API key for the cloud API | Your NEAR AI API key |
| `DATABASE_USER` | PostgreSQL username | `postgres` or your macOS username |
| `DATABASE_PASSWORD` | PostgreSQL password | `postgres` or empty for local |
| `DATABASE_NAME` | Database name | `chat_api` |

#### Optional environment variables (for OAuth)

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret |
| `FRONTEND_URL` | Frontend URL for OAuth redirects (default: `http://localhost:3000`) |
| `REDIRECT_URI` | OAuth callback base URL (default: `http://localhost:8081`) |

#### Minimal `.env` for local development

```bash
# Cloud API (required)
OPENAI_BASE_URL=https://cloud-api.near.ai/v1
OPENAI_API_KEY=your_api_key_here

# Database - adjust DATABASE_USER if 'postgres' role doesn't exist
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=chat_api
DATABASE_USER=postgres
DATABASE_PASSWORD=postgres

# Frontend
FRONTEND_URL=http://localhost:3000
CORS_ALLOWED_ORIGINS=http://localhost:3000
```

> **Note for macOS users:** If you get `FATAL: role "postgres" does not exist`, either:
> - Create the role: `createuser -s postgres`
> - Or use your username: `DATABASE_USER=$(whoami)` and `DATABASE_PASSWORD=`

### Run locally (host PostgreSQL)

Create the database if you are not using Docker:
```bash
createdb chat_api
```

Start the API:
```bash
cargo run --bin api
```

The server listens on `SERVER_HOST:SERVER_PORT` (defaults to `0.0.0.0:8081`).

### Run everything locally (Docker)

Create a `.env` file with at minimum:
```bash
# Required for cloud API proxy
OPENAI_API_KEY=your_api_key_here

# Optional: OAuth credentials for Google/GitHub login
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

> **Note:** `OPENAI_BASE_URL` defaults to `https://cloud-api.near.ai/v1` in docker-compose.yml

Start PostgreSQL and the API:
```bash
docker compose up -d
```

Rebuild after code changes:
```bash
docker compose up -d --build
```

Docker builds the bundled frontend. Ensure `.env` includes
`PRIVATE_CHAT_FRONTEND_VERSION` (see `build-config.toml`).

The API is exposed on `http://localhost:8080` in the Compose setup.

### Run API locally with Docker PostgreSQL

If you want native `cargo run` but Docker DB:
```bash
docker compose up -d postgres
cargo run --bin api
```

## Tests

```bash
# All tests with mock-login endpoint enabled
cargo test --features test

# Admin tests only
cargo test --test admin_tests --features test

# E2E tests (real OpenAI calls, ignored by default)
cargo test --test e2e_api_tests --features test -- --ignored --nocapture
```

## Frontend build (optional)

The API can serve a bundled frontend if you build it locally:
```bash
./scripts/build-frontend.sh
```

This clones the private frontend repo and places the build in
`crates/api/frontend/dist`.

## Useful notes

- `.env` is loaded automatically on startup via `dotenvy`.
- Database migrations run automatically when the API starts.
- For verbose logging, set `RUST_LOG` (e.g. `info,api=debug,services=debug`).
