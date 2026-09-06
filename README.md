# NEAR AI Private Chat API

[![Security Audit](https://github.com/nearai/chat-api/actions/workflows/security-audit.yml/badge.svg)](https://github.com/nearai/chat-api/actions/workflows/security-audit.yml)

A Rust backend service that proxies OpenAI-compatible inference requests to **NEAR AI Cloud API**. It provides OAuth authentication (Google/GitHub), user session management, and serves a frontend as static files. Designed to run in a Trusted Execution Environment (TEE) for enhanced security and privacy.

## Features

- 🔒 **TEE Execution**: Runs in a Trusted Execution Environment with cryptographic attestation
- 🤖 **OpenAI-Compatible API**: Drop-in replacement for OpenAI API endpoints (proxies to NEAR AI Cloud API)
- 🔐 **OAuth Authentication**: Google and GitHub OAuth support
- 🧠 **Stateless Responses**: `/v1/responses` always forwards requests with `store: false`
- 📊 **User Management**: Session management, user settings, and analytics
- ⚡ **Streaming**: Real-time SSE streaming for AI responses

## Architecture

### Crate Structure

```
crates/
├── api/          # Axum HTTP server, routes, middleware, OpenAPI docs (utoipa)
├── services/     # Business logic: auth, temporary read views, response proxy, user management
├── database/     # PostgreSQL (tokio-postgres, deadpool), migrations, repositories
└── config/       # Environment-based configuration structs
```

### Key Patterns

- **Repository Pattern**: Database access through trait-based repositories (`PostgresUserRepository`, etc.)
- **Service Layer**: Business logic in `services` crate, injected into `AppState`
- **NEAR AI Cloud API Proxy**: OpenAI-compatible inference routes forward to NEAR AI Cloud API with auth; Responses requests are stateless
- **Temporary Read Views**: Owner-only Conversation and File GET endpoints remain available for the Stage I migration/export window. Ordinary Conversation, File, and sharing writes return `410 Gone`; the existing `DELETE /v1/users/me` account-deletion flow remains available.
- **Patroni Support**: Optional cluster discovery for HA PostgreSQL via `DATABASE_PRIMARY_APP_ID`

### Request Flow

1. Request → its historical authentication boundary → route handler
2. `/v1/responses` → validate stateless linkage fields → forward to NEAR AI Cloud API with `store: false`
3. Temporary owner-only Conversation/File GET views → local ownership lookup and, where needed, Cloud read view
4. Usage, subscription, rate-limit, and attestation-related proxy behavior remain local to Chat API

## Development

### Prerequisites

- Rust 1.90.0 (see `rust-toolchain.toml`)
- PostgreSQL 16+ (or use Docker Compose)
- Docker and Docker Compose
- For reproducible builds: `skopeo`, `jq`, Docker BuildKit

### Setup

1. **Clone and configure**:
   ```bash
   git clone <repository-url>
   cd chat-api
   cp env.example .env
   # Edit .env with your configuration
   ```

2. **Start PostgreSQL**:
   ```bash
   docker compose up -d postgres
   ```

3. **Run the server** (migrations run automatically):
   ```bash
   cargo run --bin api
   ```

   Server starts on `http://localhost:8081`. Visit `/docs` for OpenAPI documentation.

### Docker Development

```bash
docker compose up -d              # Start all services
docker compose up -d --build      # Rebuild and start
docker compose logs -f api        # View logs
docker compose down               # Stop services
```

### Testing

```bash
cargo test --features test                            # All tests
cargo test --test admin_tests --features test         # Admin tests only
cargo test --test responses_stateless_tests --features test
cargo test --test conversations_tests --features test
cargo test --test files_tests --features test
```

### Code Quality

```bash
cargo fmt          # Format code
cargo clippy       # Run linter
cargo clippy --fix # Auto-fix issues
```

See `env.example` for all configuration options.

## Building

### Local Build

```bash
cargo build              # Debug build
cargo build --release    # Release build (output: target/release/api)
```

### Docker Build

**Standard build** (for development):
```bash
docker build -t chat-api .
```

**Reproducible build** (for production):
```bash
./scripts/build-image.sh                              # Build
./scripts/build-image.sh --push <registry>/<tag>     # Build and push
```

### Reproducible Builds

This project implements **reproducible builds** to ensure bit-for-bit identical Docker images from the same source code. Critical for security, auditability, and TEE attestation verification.

**Features**:
- Pinned Debian package versions (via APT preferences)
- Debian snapshot archives (date: `20250411T024939Z`)
- Deterministic timestamps (`SOURCE_DATE_EPOCH` set to git commit timestamp)
- Pinned base images (SHA256 digests, not tags)
- Locked dependencies (`Cargo.lock`, `pnpm-lock.yaml`, `build-config.toml`)

**Verify reproducibility**:
```bash
./scripts/build-image.sh
DIGEST1=$(skopeo inspect oci-archive:./oci.tar | jq -r .Digest)
rm -f oci.tar
./scripts/build-image.sh
DIGEST2=$(skopeo inspect oci-archive:./oci.tar | jq -r .Digest)
# Digests should match
```

**Build output**: OCI archive at `./oci.tar` with manifest digest for verification.

## TEE Hosting

This API is designed to run in a **Trusted Execution Environment (TEE)** (Intel TDX CVM), providing hardware-level security and cryptographic attestation.

**Benefits**:
- 🔒 Code integrity: Isolated, tamper-proof environment
- 🛡️ Data privacy: User data and API keys protected from host access
- ✅ Attestation: Cryptographic proofs verify execution environment
- 🔐 Confidentiality: Even cloud providers cannot access application memory

### Attestation

The API provides attestation reports via `/v1/attestation/report`:

```bash
NONCE=$(openssl rand -hex 32)
curl "https://private.near.ai/v1/attestation/report?nonce=${NONCE}&signing_algo=ecdsa"
```

Reports include:
- Intel TDX quotes (hardware-level proofs)
- Image digests (from reproducible builds)
- Event logs and cryptographic signatures
- Model provider attestations (end-to-end security)

### Deployment

- **Automatic TEE detection** via `dstack-sdk`
- **VPC authentication** for secure key management (set `VPC_SHARED_SECRET_FILE`)
- **Reproducible builds** required for attestation verification
- **Development mode**: `DEV=true` returns mock attestation data
- **Production mode**: `DEV=false` requires TEE execution and generates real attestation reports

## Database

Migrations are in `crates/database/src/migrations/sql/` and run automatically on startup. Supports PostgreSQL and Patroni clusters (via `DATABASE_PRIMARY_APP_ID`).

## API Documentation

OpenAPI docs available at `/docs`.

**Key endpoints**:
- `/v1/auth/*` - OAuth authentication
- `/v1/responses` - OpenAI-compatible, stateless Responses API (proxied to NEAR AI Cloud API)
- `/v1/conversations/*` - Temporary owner-only Conversation views for migration/export
- `/v1/files/*` - Temporary read-only File views for migration/export
- `/v1/attestation/report` - TEE attestation reports
- `/v1/users/*` - User management
- `/v1/admin/*` - Admin operations

**Stage I migration**: owner-only Conversation and File GET views remain temporarily available for authenticated private-chat data export. Ordinary Conversation, File, and sharing state writes (create/update/delete, item creation, upload, pin/archive, clone, and share-group mutation), plus unsupported methods and descendants within those legacy namespaces, return `410 Gone` with `Cache-Control: no-store` after session authentication. These views will be removed in Stage III.

**Account-deletion exception**: `DELETE /v1/users/me` remains available. Its existing asynchronous worker continues Cloud Conversation/File cleanup through Cloud API's retained, API-key/workspace-scoped resource DELETE endpoints before it performs local finalization; this flow is outside the retired session-proxy write surface.

`/v1/responses` is stateless: requests are normalized to `store: false`, and response/conversation linkage fields such as `conversation`, `previous_response_id`, and `background: true` are rejected. Clients may use custom function tools and replay their own function results; Cloud validates tool and input shapes.

**Note**: OpenAI-compatible inference requests are proxied to **NEAR AI Cloud API**. Set `OPENAI_BASE_URL` to your NEAR AI Cloud API endpoint.

## Security & Privacy

This service prioritizes privacy and data security. See `CLAUDE.md` for detailed logging and security guidelines.

**Critical Rules**:
- Never log customer conversation content, titles, or user input
- Never log security credentials (API keys, tokens, passwords)
- Only log IDs and system metrics, never user data
- All customer data must be encrypted at rest and in transit

## License

PolyForm Strict License 1.0.0 - see [LICENSE](LICENSE) file for details.
