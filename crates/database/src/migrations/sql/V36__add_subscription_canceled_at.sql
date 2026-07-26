ALTER TABLE subscriptions
    ADD COLUMN canceled_at TIMESTAMPTZ;

UPDATE subscriptions
SET canceled_at = updated_at
WHERE status = 'canceled' AND canceled_at IS NULL;
