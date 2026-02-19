-- Add columns to support deferred subscription downgrades.
-- When a user downgrades mid-cycle, we store the new price_id and the date
-- it should take effect (current_period_end), preserving the old plan until then.
ALTER TABLE subscriptions
    ADD COLUMN pending_price_id VARCHAR(255),
    ADD COLUMN downgrade_effective_at TIMESTAMPTZ;
