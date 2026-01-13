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

Edit `.env` with your values. At minimum for local dev:
- `OPENAI_API_KEY`
- `DATABASE_*` (defaults in `env.example` match the Docker Compose setup)
- Optional OAuth keys if testing real login flows

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

This starts PostgreSQL and the API:
```bash
docker compose up -d
```

Rebuild after code changes:
```bash
docker compose up -d --build
```

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
