# API Tests

These integration tests exercise Chat API's authentication, billing, proxy,
stateless Responses, and temporary Stage I read-only data views. They use the
`test` feature to enable the mock-login endpoint and require a PostgreSQL test
database.

## Stage I API coverage

- `responses_permissions_tests` verifies that stateful Responses fields fail
  locally with a stable `400` response.
- `responses_stateless_tests` verifies `store: false` forwarding, including
  client-managed function replay. Tool and input-item shapes are forwarded to
  Cloud for capability validation.
- `conversations_tests` verifies that owner-only Conversation GET views remain
  available for export while sharing APIs and all disabled stateful operations
  return `410 Gone`.
- `files_tests` verifies that existing File GET views remain available for
  export while upload and delete return `410 Gone`.

Temporary views require session authentication and ownership of the requested
Conversation or File. They and their migration responses use
`Cache-Control: no-store`. Sharing APIs, unsupported methods, and descendants
within the legacy Conversation, File, and sharing namespaces return the same
authenticated `410 Gone` migration response.

## Running tests

```bash
cargo test --features test
cargo test --test responses_permissions_tests --features test
cargo test --test conversations_tests --features test
cargo test --test files_tests --features test
```

Set the database configuration in `.env` before running integration tests. No
real Cloud API credentials are required for the retirement or local validation
tests.
