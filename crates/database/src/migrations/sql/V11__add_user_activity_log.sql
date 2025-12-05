-- User activity log for tracking user engagement metrics
-- This table stores activity events for analytics purposes

CREATE TABLE user_activity_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    activity_type VARCHAR(50) NOT NULL,  -- 'login', 'signup', 'response', 'conversation', 'file_upload'
    auth_method VARCHAR(50),             -- 'google', 'github', 'near' (only for login/signup)
    metadata JSONB,                      -- Additional context (e.g., conversation_id, file_id)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for querying by user
CREATE INDEX idx_user_activity_user_id ON user_activity_log(user_id);

-- Index for filtering by activity type
CREATE INDEX idx_user_activity_type ON user_activity_log(activity_type);

-- Index for time-based queries (analytics)
CREATE INDEX idx_user_activity_created ON user_activity_log(created_at);

-- Composite index for common analytics queries (activity type + time range)
CREATE INDEX idx_user_activity_type_created ON user_activity_log(activity_type, created_at);

-- Index for auth method analytics
CREATE INDEX idx_user_activity_auth_method ON user_activity_log(auth_method) WHERE auth_method IS NOT NULL;

