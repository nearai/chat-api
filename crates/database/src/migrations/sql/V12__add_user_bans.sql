-- User bans / blacklist table
-- Stores temporary or permanent bans for users

CREATE TABLE user_bans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason VARCHAR(255),
    ban_type VARCHAR(50) NOT NULL, -- e.g. 'near_auth_fail', 'manual'
    expires_at TIMESTAMPTZ,        -- NULL means permanent ban
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ         -- NULL when ban is active
);

-- Active bans lookup (by user)
CREATE INDEX idx_user_bans_user_active
    ON user_bans(user_id, expires_at, revoked_at)
    WHERE revoked_at IS NULL;


