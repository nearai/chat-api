CREATE TABLE user_account_deletions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'processing', 'retrying', 'completed', 'failed_needs_review')
    ),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    lease_until TIMESTAMPTZ,
    last_error TEXT,
    progress JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_account_deletions_status_lease
    ON user_account_deletions(status, lease_until);

CREATE INDEX idx_user_account_deletions_user_id
    ON user_account_deletions(user_id);

CREATE TRIGGER update_user_account_deletions_updated_at
    BEFORE UPDATE ON user_account_deletions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
