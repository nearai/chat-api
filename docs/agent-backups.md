# Historical agent backup downloads

Set `AGENT_BACKUP_EXPORT_BEFORE` to an RFC 3339 timestamp with an explicit timezone.
Only ready backups whose `created_at` is strictly earlier than this instant are
eligible. Equivalent timezone offsets are compared as instants. An unset value
disables listing and downloads with HTTP 503; an empty or invalid value fails
service initialization. Configuration changes take effect on restart.

`GET /v1/agents/instances/{id}/backups` returns `export_before` and a `backups`
array ordered newest first. Each entry contains `id`, `created_at`, `size_bytes`,
and `status`. An empty array means no eligible backup is available. The timestamp
is the start of backup creation, not a point-in-time snapshot guarantee.

`GET /v1/agents/instances/{id}/backups/{backup_id}/download` returns a signed
`url` and its lifetime in seconds as `expires_in`. Both endpoints require the
instance owner. Every link request checks the backup's current metadata,
instance association, cutoff, and ready status. An ineligible backup returns
404; a backup that is not ready returns 409. Previously issued URLs retain their
original expiry.

`POST /v1/agents/instances/{id}/backups/export` now returns HTTP 410 for the
owner. It no longer starts a new backup or accepts an additional encryption key.

Historical archives retain their original encryption recipients. To decrypt with
SSH, the user needs the private key matching a public key associated with the
backup when it was created. Changing the current SSH key does not change an
existing archive. Never request or upload the user's private key.
