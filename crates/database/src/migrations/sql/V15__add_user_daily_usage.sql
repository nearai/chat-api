-- Track per-user daily usage for rate limiting and reporting
CREATE TABLE user_daily_usage (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    usage_date DATE NOT NULL,
    request_count BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, usage_date)
);

CREATE INDEX idx_user_daily_usage_date ON user_daily_usage (usage_date);

