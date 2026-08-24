ALTER TABLE subscriptions
ADD COLUMN current_period_start TIMESTAMPTZ;

ALTER TABLE subscriptions
ADD CONSTRAINT subscriptions_period_bounds_check
CHECK (current_period_start IS NULL OR current_period_start < current_period_end);
