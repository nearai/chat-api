# Historical agent backup downloads

Set `AGENT_BACKUP_EXPORT_BEFORE` to an RFC 3339 timestamp with an explicit timezone.
Only ready backups whose `created_at` is strictly earlier than this instant are
eligible. Equivalent timezone offsets are compared as instants. An unset value
disables historical listing and downloads with HTTP 503 (unless fresh exports are enabled); an empty or invalid value fails
service initialization. Configuration changes take effect on restart.

`GET /v1/agents/instances/{id}/backups` returns `export_before` and a `backups`
array ordered newest first. Optional `limit` (1–1000, default 100) and `offset`
(non-negative safe integer, default 0) paginate the eligible rows. The metadata
API must support creation-time/status filters before limit/offset. To retrieve
only the newest eligible backup, request `?limit=1&offset=0`. Concurrent additions
or deletions can shift offset pages. Each returned page is bounded; no complete
backup history is fetched for a list request.

The array is ordered newest first. Each entry contains `id`, `created_at`, `size_bytes`,
and `status`. An empty array means no eligible backup is available. The timestamp
is the start of backup creation, not a point-in-time snapshot guarantee.

`GET /v1/agents/instances/{id}/backups/{backup_id}/download` returns a signed
`url` and its lifetime in seconds as `expires_in`. Both endpoints require the
instance owner. Every link request checks the backup's current metadata,
instance association, cutoff, and ready status. An ineligible backup returns
404; a backup that is not ready returns 409. Previously issued URLs retain their
original expiry.

Fresh exports are disabled by default. Set `AGENT_BACKUP_EXPORT_CREATE_ENABLED=true`
to enable `POST /v1/agents/instances/{id}/backups/export` and downloads of ready
backups regardless of the historical cutoff. Only the exact value `true` enables
this mode; unset or any other value keeps creation disabled (HTTP 410). The flag
is independent of `AGENT_BACKUP_EXPORT_BEFORE`: historical listings still require
and enforce their cutoff, while enabled fresh exports and downloads work without it.

The export endpoint accepts `{ "export_ssh_pubkey": "<SSH public key>" }` or `{}`
and streams backup progress as SSE. The optional public key adds a recipient for
the new archive; it does not re-encrypt existing backups. Ownership, metadata
association, valid backup IDs, and ready-status checks remain enforced for every
download in either mode. Disabling fresh exports reinstates cutoff checks for new
link requests; previously issued URLs retain their original expiry.

Historical archives retain their original encryption recipients. To decrypt with
SSH, the user needs the private key matching a public key associated with the
backup when it was created. Changing the current SSH key does not change an
existing archive. Never request or upload the user's private key.
