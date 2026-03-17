-- Table for purchased credits per user.
-- Unit: nano-USD (1e-9 USD; 1_000_000_000 = $1). Same unit as cost_nano_usd and monthly_credits.
-- Remaining = total_nano_usd - spent_nano_usd (computed, not stored).
CREATE TABLE user_credits (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    total_nano_usd BIGINT NOT NULL DEFAULT 0 CHECK (total_nano_usd >= 0),
    -- Lifetime spent from purchased pool.
    spent_nano_usd BIGINT NOT NULL DEFAULT 0 CHECK (spent_nano_usd >= 0),
    -- Track how much "over plan" usage we've already applied for the current period,
    -- so reconcile_purchased_after_usage can be safely called multiple times.
    last_reconciled_period_start TIMESTAMPTZ,
    last_reconciled_over_plan_nano_usd BIGINT NOT NULL DEFAULT 0 CHECK (last_reconciled_over_plan_nano_usd >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (spent_nano_usd <= total_nano_usd)
);

COMMENT ON COLUMN user_credits.total_nano_usd IS 'Cumulative purchased+granted credits (nano-USD)';
COMMENT ON COLUMN user_credits.spent_nano_usd IS 'Lifetime consumed from purchased pool (nano-USD). Remaining = total_nano_usd - spent_nano_usd.';
COMMENT ON COLUMN user_credits.last_reconciled_period_start IS 'Start timestamp of the billing period used for last over-plan reconciliation.';
COMMENT ON COLUMN user_credits.last_reconciled_over_plan_nano_usd IS 'Over-plan usage (nano-USD) already applied to spent_nano_usd for last_reconciled_period_start.';

-- Trigger for updating updated_at timestamp on user_credits
CREATE TRIGGER update_user_credits_updated_at
    BEFORE UPDATE ON user_credits
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Table for credit transaction audit (purchases, grants, admin adjustments).
-- amount is in nano-USD (same unit as user_credits totals).
CREATE TABLE credit_transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount BIGINT NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (type IN ('purchase', 'grant', 'admin_adjust')),
    reference_id VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial unique index: prevents double-credit on webhook retries for purchases
CREATE UNIQUE INDEX idx_credit_transactions_purchase_ref
    ON credit_transactions(reference_id) WHERE type = 'purchase' AND reference_id IS NOT NULL;

-- Index for querying transactions by user
CREATE INDEX idx_credit_transactions_user_id ON credit_transactions(user_id);
