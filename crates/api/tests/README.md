# API Tests

These integration tests exercise Chat API's authentication, billing, proxy, and
stateless Responses boundaries. They use the `test` feature to enable the
mock-login endpoint and require a PostgreSQL test database.

## Stateless API coverage

- `responses_permissions_tests` verifies that stateful Responses fields fail
  locally with a stable `400` response.
- `conversations_tests` and `files_tests` verify that the retired stateful API
  surfaces return the same `410 Gone` migration response after their historical
  authentication boundary, without reaching Cloud API or local state services.

The retired paths are intentionally absent from OpenAPI. They are still mounted
at their historical authentication boundaries so clients receive a clear
migration response instead of a proxy failure.

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
