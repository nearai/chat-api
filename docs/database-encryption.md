# Database field encryption

This runbook covers the whole-database confidential-field migration initiated by
issue #394 before database access leaves the CVM/TEE boundary.

## Key configuration

Use a dedicated 32-byte AES key encoded as 64 hexadecimal characters. Supply it
through `DB_ENCRYPTION_KEY_FILE` (preferred) or `DB_ENCRYPTION_KEY`; never reuse
`ENCRYPTION_KEY`, which protects legacy agent provisioning secrets. Set a stable
`DB_ENCRYPTION_KEY_ID` identifying the deployed key version.

`DB_ENCRYPTION_WRITE_ENABLED` defaults to `false`. When false, repository reads
accept legacy plaintext and encrypted envelopes, while writes remain plaintext.
Execute-mode backfills are rejected.

Agent provisioning secrets have a separate rollout gate,
`DB_ENCRYPTION_AGENT_SECRETS_WRITE_ENABLED`, also defaulting to `false`. While
this gate is disabled, these three fields continue to use legacy app-key
encryption rather than plaintext. Enabling it requires the global write gate
to be enabled too; otherwise credential writes fail. Reads support both formats
independently of the write gates. See
[Migrate legacy agent credentials](#migrate-legacy-agent-credentials).

The envelope uses AES-256-GCM and authenticates the table, column, and stable row
UUID. Equality indexes use domain-separated HMAC-SHA256 tokens; tokens are not
reused between fields. Ciphertext, tokens, keys, nonces, and row values must not
be logged.

## Rollout

1. Configure the same dedicated key and key ID on every replica, leave writes
   disabled, and deploy dual-read support.
2. Confirm all old replicas have drained.
3. Set `DB_ENCRYPTION_WRITE_ENABLED=true` and deploy again.
4. Call `POST /v1/admin/database-encryption/scan` with an empty scope. Treat the
   capped scan as diagnostic; it is not the release gate for large tables.
5. Create explicit-scope dry-run jobs, then execute jobs in small batches. Poll
   `GET /v1/admin/database-encryption/jobs/{job_id}`. Jobs resume from durable
   cursors after restart and can be cancelled at a transaction boundary.
6. Call `POST /v1/admin/database-encryption/verify` and poll its returned job.
   Do not move the database or backups outside the CVM boundary unless `pass` is
   true and plaintext, legacy-encrypted, and invalid-envelope counts are zero.

V39 deliberately retains the legacy share and group uniqueness/index arbiters
for rolling-deployment compatibility. Remove them only in a separately reviewed
cleanup migration after all old replicas have drained and the backfill and
verification jobs have completed.

Suggested execute request:

```json
{
  "mode": "execute",
  "scope": {"tables": ["files"]},
  "batch_size": 100,
  "max_rows": null,
  "actions": ["encrypt"]
}
```

## Recovery and rollback constraints

Jobs resolve the requested tables into an explicit field list when created and
return that list in `scope`. Recovery uses this saved list, so adding a registered
field does not expand existing jobs. Older jobs with table-level or empty scopes
stop with `last_error_class: "scope_requires_confirmation"` before processing
another batch. Review the intended fields and create a new dry-run/execute job;
do not edit the stored scope or reuse its cursor. Old jobs that already specify
individual fields can resume normally.

Jobs commit one bounded batch at a time. Retrying an interrupted job is safe:
authenticated envelopes are detected and skipped, and cursor/progress state is
durable. The active-scope index prevents duplicate jobs for the same canonical
scope, and the process-local worker semaphore prevents connection-pool
exhaustion. A PostgreSQL session advisory lock held for the complete job
serializes workers across replicas. A failed deploy may be
rolled back only to a version that supports dual reads; rolling back to a
plaintext-only reader after encrypted writes begin makes data unreadable.

Never remove an old key until a separately reviewed rotation job has rewritten
and verified every envelope carrying its key ID. Database backups containing
legacy plaintext remain confidential and must stay inside the original trust
boundary or be destroyed under the backup-retention policy.

## Registered confidential fields

- `files.filename`
- `conversation_share_groups.name`
- `conversation_share_group_members.member_value`
- `conversation_shares.recipient_value`
- `oauth_tokens.access_token`
- `oauth_tokens.refresh_token`
- `agent_instances.auth_session_token`
- `agent_instances.instance_url`
- `agent_instances.dashboard_url`
- `agent_instances.instance_token`
- `user_passkey_credentials.auth_secret`
- `user_passkey_credentials.backup_passphrase`

The passkey table uses its unique `user_id` UUID as the authenticated row
context, not its serial primary key. Reads, writes, and backfills use the same
context.

File content is not stored in this database; verify object-storage encryption
separately. Legacy `conversations.title` and the dropped `response_authors` table
must be confirmed absent in every deployed database and backup.

Organization email patterns remain approved plaintext because the API supports
arbitrary SQL wildcard patterns and deterministic equality tokens cannot
preserve those matching semantics. Cloud API file IDs have the form
`file-<UUID>`; the embedded UUID is the authenticated encryption context for
`files.filename`. Before enabling writes, confirm every existing `files.id`
matches that format. Nonconforming IDs are skipped by execute jobs and cause
verification to fail with a missing encryption context.

## Whole-database policy classification

The inventory enumerates every column in every application base table, across
all PostgreSQL data types. Fields selected for encryption and fields explicitly
approved for plaintext storage outside the TEE are registered individually.
Account/profile, OAuth/session, billing, AML, passkey, agent, configuration,
deletion, and broader usage fields not listed above were reviewed and approved
as plaintext by policy. New tables outside these policies and new columns in
the individually classified encryption tables are `unclassified` and fail
verification. A deployed legacy `conversations.title` column or
`response_authors` table is reported as `legacy_confidential` and also fails
verification.

For completed jobs in every mode, invalid ciphertext or an invalid search token
makes `progress.pass` false. A completed `dry_run` or `execute` job with `pass=true`
only means no such errors were found in the processed rows; bounded jobs may
leave rows unprocessed. Agent-credential decryption failures during `execute`
fail the job and roll back its current batch.

Only a completed, unbounded `verify` job with `pass=true` confirms compliance
with the reviewed policy for its scope. It also rejects remaining plaintext,
legacy app-key ciphertext, missing row contexts, unclassified columns, and
legacy confidential conversation data. It does not mean that every database
value is encrypted.

## Migrate legacy agent credentials

Complete this migration **under the existing app key before changing the KMS
root**. It covers `agent_instances.instance_token` and both passkey fields listed
above. It does not change routing or deploy a new KMS.

1. Finish or cancel existing backfill jobs. Start one new-version API canary
   outside user traffic with `DB_ENCRYPTION_AGENT_SECRETS_WRITE_ENABLED=false`.
   Keep the existing `DB_ENCRYPTION_KEY`, key ID, and `ENCRYPTION_KEY` unchanged.
   Do not turn off already-enabled field encryption for other columns.
2. Use the canary to scan and run an **unbounded dry-run** of the explicit scope
   below before replacing the serving replicas. Require `status: "completed"`,
   `progress.pass: true`, and zero `invalid_envelopes`. A capped scan alone is
   not sufficient. Fix unreadable rows or key configuration before continuing.
   `legacy_encrypted` counts valid app-key ciphertext still needing conversion;
   dry-run does not rewrite data.
3. Deploy this version to all API replicas and task workers, keeping the new
   gate false. Confirm every old reader and writer has drained. Reads accept
   field envelopes, legacy ciphertext, and historical plaintext. Test existing
   agent authentication and passkey login/recovery before enabling new writes.
4. Set both `DB_ENCRYPTION_WRITE_ENABLED=true` and
   `DB_ENCRYPTION_AGENT_SECRETS_WRITE_ENABLED=true` on all API replicas and
   workers. Ensure deployment configuration passes the new variable through to
   each process. Finish this rollout before backfilling so no writer can create
   more legacy ciphertext.
5. Submit the same request with `mode: "execute"` and poll the job to completion.
   Each legacy value is decrypted first and its plaintext encrypted under the
   field key. A credential decryption failure rolls back the current batch and
   fails the job. Earlier committed batches remain converted; after fixing the
   cause, a new job safely skips valid field envelopes.
6. Call `/v1/admin/database-encryption/verify` with this scope and no `max_rows`.
   Require `status: "completed"` and `progress.pass: true`. A capped scan or a
   dry-run is not proof that all credentials have been converted.
7. Test a controlled deployment under the new KMS root with the **same field key
   and key ID**. Verify existing agent authentication, passkey login/recovery,
   and credential creation/update. Only then proceed with the production root
   cutover. Do not export the old app key as a workaround.

Dry-run request for `POST /v1/admin/database-encryption/jobs`:

```json
{
  "mode": "dry_run",
  "scope": {
    "fields": [
      {"table": "agent_instances", "column": "instance_token"},
      {"table": "user_passkey_credentials", "column": "auth_secret"},
      {"table": "user_passkey_credentials", "column": "backup_passphrase"}
    ]
  },
  "batch_size": 100,
  "actions": ["encrypt"]
}
```

Legacy ciphertext is identified by its 24-character hexadecimal nonce followed
by `:`. Other plaintext credentials may contain colons. Once that prefix or the
field-envelope marker is recognized, malformed ciphertext and decryption errors
are never treated as plaintext. Missing or incorrect keys fail authentication
lookups and migration validation even while the new write gate is false.

User/admin instance lists omit an unreadable `instance_token` and emit a warning
containing only the instance ID, so one bad token does not hide the other rows.
A successful list response is not proof that every credential is readable.

Once new writes or backfills begin, rollback must retain dual-read support.
Disabling the new gate under the old root resumes legacy writes; verification
must be repeated before cutover. Do not disable it after changing roots.
Backups containing old app-key ciphertext still need the old key to restore
those credentials; handle that dependency under the backup-retention policy
before retiring the old root. Deployment does not create a backfill job;
previously queued or running jobs are resumed.

## Approved operational plaintext

Internal relationship UUIDs, timestamps, status/permission enums, booleans,
counters, sizes, non-reversible hashes/MACs, and file purpose remain approved
operational plaintext. Opaque provider conversation/file IDs and the associated
share relationship also remain plaintext: they are protocol-facing primary and
foreign keys, authorization is enforced independently of possessing an ID, and
an internal-key migration would provide limited protection while relationship
structure remains visible. They must not be treated as authorization secrets or
included in logs.
