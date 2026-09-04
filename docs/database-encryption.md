# Conversation and file database encryption

This runbook covers the whole-database confidential-field migration initiated by
issue #394 before database access leaves the CVM/TEE boundary.

## Key configuration

Use a dedicated 32-byte AES key encoded as 64 hexadecimal characters. Supply it
through `DB_ENCRYPTION_KEY_FILE` (preferred) or `DB_ENCRYPTION_KEY`; never reuse
`ENCRYPTION_KEY`, which protects agent provisioning secrets. Set a stable
`DB_ENCRYPTION_KEY_ID` identifying the deployed key version.

`DB_ENCRYPTION_WRITE_ENABLED` defaults to `false`. When false, repository reads
accept legacy plaintext and encrypted envelopes, while writes remain plaintext.
Execute-mode backfills are rejected.

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
   true and plaintext/invalid-envelope counts are zero.

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

Jobs commit one bounded batch at a time. Retrying an interrupted job is safe:
authenticated envelopes are detected and skipped, and cursor/progress state is
durable. The active-scope index prevents two workers from processing the same
canonical scope, and the process-local worker semaphore prevents connection-pool
exhaustion. A transaction-scoped PostgreSQL advisory lock also serializes
batches across replicas without leaking a session lock. A failed deploy may be
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
- `conversation_shares.org_email_pattern`
- `user_activity_log.metadata`

File content is not stored in this database; verify object-storage encryption
separately. Legacy `conversations.title` and the dropped `response_authors` table
must be confirmed absent in every deployed database and backup.

## Whole-database classification

The inventory enumerates every column in every application base table, across
all PostgreSQL data types. Implemented encrypted fields and approved operational
columns are registered individually. Account/profile, OAuth/session, billing,
AML, passkey, agent, configuration, deletion, and broader usage tables are
reported field-by-field as `encryption_required`; they are never silently
treated as approved plaintext. New tables outside these policies and new
columns in the individually classified encryption tables are `unclassified` and
fail verification. A deployed legacy `conversations.title` column or
`response_authors` table is reported as `legacy_confidential` and also fails
verification.

`encryption_required` fields fail the whole-database release gate until their
repository-aware designs for lookup tokens, uniqueness, foreign keys,
retention, and credential lifecycle are implemented and verified.

## Approved operational plaintext

Internal relationship UUIDs, timestamps, status/permission enums, booleans,
counters, sizes, non-reversible hashes/MACs, and file purpose remain approved
operational plaintext. Opaque provider conversation/file IDs and the associated
share relationship also remain plaintext: they are protocol-facing primary and
foreign keys, authorization is enforced independently of possessing an ID, and
an internal-key migration would provide limited protection while relationship
structure remains visible. They must not be treated as authorization secrets or
included in logs.
