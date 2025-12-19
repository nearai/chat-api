# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 🔒 PRIVACY & DATA SECURITY - CRITICAL

**Privacy and data security are THE most important aspects of this service for customer/client trust.**

### Logging Rules (ABSOLUTE REQUIREMENTS)

Production runs at **info level and above**. We ABSOLUTELY CANNOT and SHOULD NOT log customer-related data.

#### ✗ NEVER LOG (Forbidden)
- **Security credentials** - API keys, session tokens, passwords, secrets, OAuth tokens, encryption keys (these could compromise security if leaked)
- **Conversation content** - Any message text, completion text, or AI-generated content
- **Conversation titles** - User-provided or AI-generated conversation names
- **Conversation descriptions** - Any descriptive text about conversations
- **User input** - Messages, prompts, or any user-submitted text
- **AI responses** - Model outputs, completions, or generated text
- **Metadata that reveals customer information** - Custom fields, tags, labels that could expose user activity
- **File contents** - Uploaded file data or processed file content
- **Any PII** - Names, emails (except for auth flow), addresses, phone numbers in user content

#### ✓ OK TO LOG (Permitted for Debugging)
- **IDs only** - `conversation_id`, `user_id`, `session_id`, `response_id`
- **System metrics** - Request counts, latency, token counts (numbers only)
- **Error types** - Error codes, HTTP status codes, error categories
- **System events** - Server startup, shutdown, connection pool status
- **Authentication events** - Login attempts, session creation (not passwords/tokens)

#### Guidelines for Adding Logging
1. **Before adding any log statement**: Ask yourself "Could this reveal anything about a customer's conversation or activity?"
2. **If in doubt, don't log it** - Err on the side of caution
3. **Log IDs, not content** - Use `conversation_id` not conversation title
4. **Review all logging changes carefully** - Every log statement is a potential privacy leak
5. **Use debug/trace levels for detailed data** - These are not enabled in production
6. **Never log request/response bodies** - Even at debug level, unless you're 100% certain they don't contain customer data

#### Examples

**❌ BAD - NEVER DO THIS:**
```rust
tracing::info!("API key: {}", api_key);  // Security risk - exposes credentials!
tracing::info!("Creating conversation: {}", conversation.title);  // Exposes title!
tracing::info!("User message: {}", message.content);  // Exposes content!
tracing::warn!("Invalid input: {}", user_input);  // Exposes user data!
tracing::debug!("Session token: {}", session_token);  // Security risk!
```

**✅ GOOD - Do this instead:**
```rust
tracing::info!("API key validated: user_id={}", user_id);  // Only log ID
tracing::info!("Creating conversation: conversation_id={}", conversation.id);
tracing::info!("Processing message: conversation_id={}, user_id={}", conv_id, user_id);
tracing::warn!("Invalid input format: conversation_id={}", conversation_id);
tracing::debug!("Session validated: session_id={}, user_id={}", session_id, user_id);
```

### Security Reminders
- This service runs in a **Trusted Execution Environment (TEE)** - customer trust is paramount
- All customer data must be encrypted at rest and in transit
- Session tokens are SHA-256 hashed before storage
- Never commit secrets or credentials to the repository
- All authentication flows use HTTPS/TLS

---

## Project Overview

NEAR AI Chat API - A Rust backend that proxies OpenAI API requests while tracking user conversations in PostgreSQL. Provides OAuth authentication (Google/GitHub), user session management, and a frontend served as static files.

## Build & Development Commands

```bash
# Build
cargo build                    # Debug build
cargo build --release          # Release build

# Run locally (requires PostgreSQL and .env file)
cargo run --bin api

# Run tests
cargo test --features test                    # All tests with mock-login endpoint
cargo test --test admin_tests --features test # Admin tests only

# E2E tests (make real OpenAI API calls, require valid credentials)
cargo test --test e2e_api_tests --features test -- --ignored --nocapture

# Run a specific test
cargo test --test e2e_api_tests test_conversation_workflow --features test -- --ignored --nocapture
```

## Docker Development

```bash
docker compose up -d           # Start PostgreSQL + API
docker compose up -d --build   # Rebuild and start
```

## Architecture

### Crate Structure

```
crates/
├── api/          # Axum HTTP server, routes, middleware, OpenAPI docs (utoipa)
├── services/     # Business logic: auth, conversation, response proxy, user management
├── database/     # PostgreSQL (tokio-postgres, deadpool), migrations, repositories
└── config/       # Environment-based configuration structs
```

### Key Patterns

- **Repository Pattern**: Database access through trait-based repositories (`PostgresUserRepository`, etc.)
- **Service Layer**: Business logic in `services` crate, injected into `AppState`
- **OpenAI Proxy**: All `/v1/*` routes forward to OpenAI with auth; conversation endpoints (`/v1/conversations/*`) track IDs in PostgreSQL
- **Patroni Support**: Optional cluster discovery for HA PostgreSQL via `DATABASE_PRIMARY_APP_ID`

### Request Flow

1. Request → Auth middleware (validates session token) → Route handler
2. Conversation operations → Forward to OpenAI → Parse response → Track in DB
3. Generic `/v1/{*path}` → Forward to OpenAI (pass-through)

### Database

- Migrations: `crates/database/src/migrations/sql/V*.sql` (refinery)
- Runs automatically on startup in `main.rs`
- Default connection: `localhost:5432/chat_api` (see `config/src/lib.rs` for env vars)

## Environment Variables

Key variables (see `crates/config/src/lib.rs` for defaults):

- `DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_NAME`, `DATABASE_USER`, `DATABASE_PASSWORD`
- `OPENAI_API_KEY`, `OPENAI_BASE_URL` (optional)
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`
- `CORS_ALLOWED_ORIGINS`, `AUTH_ADMIN_DOMAINS`
- `RUST_LOG` (e.g., `info,api=debug,services=debug,database=debug`)

## Testing Notes

- `--features test` enables `/v1/auth/mock-login` for test authentication
- E2E tests are `#[ignore]` because they call real OpenAI APIs
- Tests expect PostgreSQL running with correct schema
