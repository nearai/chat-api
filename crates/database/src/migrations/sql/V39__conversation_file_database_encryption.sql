-- Durable state for admin encryption scans/backfills.
CREATE TABLE database_encryption_jobs (
    id UUID PRIMARY KEY,
    mode TEXT NOT NULL CHECK (mode IN ('dry_run', 'execute', 'verify')),
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    scope JSONB NOT NULL,
    actions JSONB NOT NULL,
    batch_size BIGINT NOT NULL CHECK (batch_size BETWEEN 1 AND 1000),
    max_rows BIGINT CHECK (max_rows IS NULL OR max_rows > 0),
    cursor JSONB NOT NULL DEFAULT '{}'::jsonb,
    progress JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_error_class TEXT,
    last_error_message TEXT,
    admin_actor UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    cancel_requested_at TIMESTAMPTZ
);

CREATE INDEX idx_database_encryption_jobs_status
    ON database_encryption_jobs(status, created_at);
CREATE UNIQUE INDEX idx_database_encryption_jobs_active_scope
    ON database_encryption_jobs ((scope::text))
    WHERE status IN ('queued', 'running');

-- Provider file IDs remain the protocol-facing primary key during Stage I.
-- A stable internal UUID is used as authenticated encryption context.
ALTER TABLE files
    ADD COLUMN encryption_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    ALTER COLUMN filename TYPE TEXT;
CREATE UNIQUE INDEX idx_files_encryption_id ON files(encryption_id);

-- Randomized ciphertext cannot satisfy equality/uniqueness lookups. Store
-- domain-separated HMAC-SHA256 tokens alongside encrypted display values.
ALTER TABLE conversation_share_groups
    ALTER COLUMN name TYPE TEXT,
    ADD COLUMN name_search_token BYTEA;
ALTER TABLE conversation_share_groups DROP CONSTRAINT IF EXISTS conversation_share_groups_owner_user_id_name_key;
CREATE UNIQUE INDEX idx_share_groups_owner_name_token
    ON conversation_share_groups(owner_user_id, name_search_token)
    WHERE name_search_token IS NOT NULL;

ALTER TABLE conversation_share_group_members
    ALTER COLUMN member_value TYPE TEXT,
    ADD COLUMN member_value_search_token BYTEA;
ALTER TABLE conversation_share_group_members DROP CONSTRAINT IF EXISTS conversation_share_group_memb_group_id_member_type_member_v_key;
DROP INDEX IF EXISTS idx_conversation_share_group_members_value;
CREATE UNIQUE INDEX idx_share_group_members_token
    ON conversation_share_group_members(group_id, member_type, member_value_search_token)
    WHERE member_value_search_token IS NOT NULL;
CREATE INDEX idx_share_group_members_lookup_token
    ON conversation_share_group_members(member_type, member_value_search_token);

ALTER TABLE conversation_shares
    ALTER COLUMN recipient_value TYPE TEXT,
    ALTER COLUMN org_email_pattern TYPE TEXT,
    ADD COLUMN recipient_value_search_token BYTEA,
    ADD COLUMN org_domain_search_token BYTEA;
DROP INDEX IF EXISTS idx_conversation_shares_recipient;
DROP INDEX IF EXISTS idx_conversation_shares_org_pattern;
DROP INDEX IF EXISTS idx_conversation_shares_direct_unique;
DROP INDEX IF EXISTS idx_conversation_shares_org_unique;
CREATE INDEX idx_conversation_shares_recipient_token
    ON conversation_shares(recipient_type, recipient_value_search_token);
CREATE INDEX idx_conversation_shares_org_domain_token
    ON conversation_shares(org_domain_search_token);
CREATE UNIQUE INDEX idx_conversation_shares_direct_token_unique
    ON conversation_shares(conversation_id, recipient_type, recipient_value_search_token)
    WHERE share_type = 'direct' AND recipient_value_search_token IS NOT NULL;
CREATE UNIQUE INDEX idx_conversation_shares_org_token_unique
    ON conversation_shares(conversation_id, org_domain_search_token)
    WHERE share_type = 'organization' AND org_domain_search_token IS NOT NULL;
