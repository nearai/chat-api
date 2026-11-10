# Cloud API authentication

The API, MCP proxy, and task worker use only the configured static upstream key.
Set `OPENAI_API_KEY`, or set `OPENAI_API_KEY_FILE` to read the key from a file.
The file source takes precedence when configured. An unreadable file is a
configuration error; it does not fall back to the environment variable.

Both API and worker validate that the configured key is nonblank before connecting
to the database or accepting work. This only checks credential availability.
Validate the key's permissions with a real authenticated inference request before
rolling out the image. `OPENAI_BASE_URL` continues to select the upstream endpoint.

Persisted `vpc_api_key`, `vpc_organization_id`, and legacy `vpc_refresh_token` values
are no longer read, refreshed, or deleted by upstream authentication. An invalid
or disabled database key cannot override the configured static key. Existing rows
are left untouched for rollback. VPC login, the credential cache and its repository
interface, and `POST /v1/admin/vpc/revoke` have been removed.

## Deployment and key changes

Provision a valid static key for the intended Cloud API organization/workspace in
both API and worker environments before deploying this image. Deployments that
only have persisted credentials will fail startup. The infrastructure
`chat_api_static_key` option supplies the static credential and removes obsolete
VPC login environment variables; it is not an application authentication-mode
switch.

The configured key is loaded at startup. To replace a disabled or revoked key,
update its environment/file source and restart or redeploy every API and worker
process. Changing the file alone does not reload running processes. No database
credential reset or admin browser session is needed. An upstream authentication
failure is returned without retrying the request with a different identity.

Do not print key values. Keep the original credential recovery record for rollback.
Older images may select the persisted VPC key again when rolled back.

VPC hostname/server metadata in attestation reports remains available. This change
does not remove VPC networking or the separate VPC-derived database field-encryption
key. Those migrations must still be completed before retiring their dependencies.
