-- User usage event for rate limiting (tokens, images, cost in nano-dollars)
-- Replaces user_usage_log with generic metric_key + quantity design

CREATE TABLE user_usage_event (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    metric_key    TEXT NOT NULL,
    quantity      BIGINT NOT NULL,
    cost_nano_usd BIGINT,

    model_id      TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT user_usage_event_metric_key_check
        CHECK (metric_key IN ('llm.tokens', 'image.generate', 'image.edit'))
);

CREATE INDEX idx_user_usage_event_created ON user_usage_event(created_at);
CREATE INDEX idx_user_usage_event_user_created ON user_usage_event(user_id, created_at);

COMMENT ON TABLE user_usage_event IS 'Per-event usage for rate limiting (tokens, images, cost in nano-dollars)';
COMMENT ON COLUMN user_usage_event.cost_nano_usd IS 'Cost in nano-dollars (10^-9 USD), nullable';
