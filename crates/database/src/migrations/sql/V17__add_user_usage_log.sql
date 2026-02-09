-- User usage log for token and cost rate limiting
-- Stores per-response token usage and optional cost (nano-dollars, scale 9) per user

CREATE TABLE user_usage_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tokens_used BIGINT NOT NULL,
    cost_nano_usd BIGINT,  -- nullable; nano-dollars (scale 9), same as cloud-api
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_usage_created ON user_usage_log(created_at);
CREATE INDEX idx_user_usage_user_created ON user_usage_log(user_id, created_at);

COMMENT ON TABLE user_usage_log IS 'Per-response token and cost usage for rate limiting (cost in nano-dollars, scale 9)';
COMMENT ON COLUMN user_usage_log.cost_nano_usd IS 'Cost in nano-dollars (10^-9 USD), nullable';
