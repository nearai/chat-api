ALTER TABLE subscriptions
    ADD COLUMN canceled_at TIMESTAMPTZ;

UPDATE subscriptions
SET canceled_at = CASE
    WHEN provider = 'house-of-stake' THEN LEAST(updated_at, current_period_end)
    ELSE updated_at
END
WHERE status = 'canceled' AND canceled_at IS NULL;
