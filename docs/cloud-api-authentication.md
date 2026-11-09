# Cloud API authentication during VPC retirement

Both the API and task worker always use the shared credential service. Selection is:

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

VPC login, its request-signing code, and shared-secret loading have been removed.
`VPC_SHARED_SECRET_FILE` and `VPC_CLIENT_ID` no longer affect authentication, even
if an old deployment leaves them set. VPC hostname/server metadata in attestation
reports remains separate from authentication and is retained.

The legacy `vpc_*` database keys, Rust credential-service names and admin revoke
route are retained for compatibility; they do not enable VPC login. Existing DB
credentials are reused without rewriting or reprovisioning their identity.

Before deploying this image, configure the same-tenant fallback for both API and
worker and verify the persisted pair. The infrastructure `chat_api_static_key`
flag now supplies the fallback and removes obsolete login environment variables;
it is no longer an application login-mode switch. Coordinate its activation
with the image rollout, rather than first deploying the new image under old
VPC-only credential delivery. Old images may still use VPC login or static-only
mode depending on their configuration.

Removing Cloud API login does not remove the separate VPC-derived database
field-encryption key or VPC networking. Complete the DB key rotation and ingress
migration before retiring those dependencies.

## Invalid or revoked cached keys

There is no automatic upstream-401 retry or switch of identity. This avoids
replaying mutations and streams. An authorized operator must explicitly clear
persisted/local credentials using `POST /v1/admin/vpc/revoke`, then restart or
invalidate every other API/worker process that may retain the old key. The route
name is kept for compatibility; it clears local/DB caches, not the upstream key.
Invalidation remains available after VPC login removal. A failed invalidation
must be investigated before declaring fallback active. Validate the fallback's
organization/workspace and permissions before clearing the old credential.

Do not print cache contents or fallback keys. Preserve the database and original
credential recovery record for rollout/rollback. Test cache-hit startup, an empty
cache with the same-tenant fallback, cache-miss without a fallback, database error,
and invalidation in staging before production activation. Production remains
stopped during the separate infrastructure staging rollout.
