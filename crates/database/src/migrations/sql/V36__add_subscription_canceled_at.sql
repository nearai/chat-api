ALTER TABLE subscriptions
    ADD COLUMN canceled_at TIMESTAMPTZ;

UPDATE subscriptions
SET canceled_at = updated_at
WHERE status = 'canceled' AND canceled_at IS NULL;

CREATE INDEX idx_subscriptions_user_canceled_anchor
    ON subscriptions(user_id, (COALESCE(canceled_at, updated_at)) DESC)
    WHERE status = 'canceled';
