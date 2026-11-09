# Cloud API authentication during VPC retirement

Both the API and task worker use the shared credential service. With
`VPC_SHARED_SECRET_FILE` absent, selection is:

1. The process's cached selection.
2. The persisted `vpc_organization_id` / `vpc_api_key` pair in `app_config`.
3. `OPENAI_API_KEY` (or the existing `OPENAI_API_KEY_FILE` configuration source).

A persisted pair is usable only when both fields are present and nonblank. Its
organization identity is preserved. The static fallback must be provisioned for
the same existing organization/workspace; the service does not derive or verify
an organization ID from a static key. It does not overwrite the persisted pair
with the fallback. Static selection is cached in memory to avoid DB reads per
request. Restart or explicit invalidation rechecks persistence.

Startup validates credential availability for both API and worker. An empty cache
and absent/blank fallback produce an explicit error. Database errors fail closed;
they are not treated as a cache miss. Credential availability is not proof that
Cloud API accepts the key: validate with a real authorized request.

No VPC login request is possible in this mode. Merely leaving
`VPC_SHARED_SECRET_FILE` empty does not disable login: omit the variable entirely.
When it is configured, legacy cache-first VPC login behavior is preserved for
compatibility. Deploy this application change before enabling the infrastructure
`chat_api_static_key` flag; that flag now means cached credentials with a static
fallback on compatible images, whereas old images select static-only mode.

## Invalid or revoked cached keys

There is no automatic upstream-401 retry or switch of identity. This avoids
replaying mutations and streams. An authorized operator must explicitly clear
persisted/local credentials using `POST /v1/admin/vpc/revoke`, then restart or
invalidate every other API/worker process that may retain the old key. The route
name is kept for compatibility; it clears local/DB caches, not the upstream key.
Its invalidation now works even with VPC login disabled. A failed invalidation
must be investigated before declaring fallback active. Validate the fallback's
organization/workspace and permissions before clearing the old credential.

Do not print cache contents or fallback keys. Preserve the database and original
credential recovery record for rollout/rollback. Test cache-hit startup, an empty
cache with the same-tenant fallback, cache-miss without a fallback, database error,
and invalidation in staging before production activation. Production remains
stopped during the separate infrastructure staging rollout.
