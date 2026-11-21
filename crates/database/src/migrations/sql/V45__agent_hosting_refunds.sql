-- A charge is reserved once across sunset refund attempts, including failed attempts.
CREATE TABLE agent_hosting_refunds (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    subscription_id VARCHAR(255) NOT NULL,
    invoice_id VARCHAR(255) NOT NULL UNIQUE,
    customer_id VARCHAR(255) NOT NULL,
    charge_id VARCHAR(255) NOT NULL UNIQUE,
    amount BIGINT NOT NULL CHECK (amount > 0),
    currency VARCHAR(3) NOT NULL,
    livemode BOOLEAN NOT NULL,
    effective_at TIMESTAMPTZ NOT NULL,
    policy_reference VARCHAR(100) NOT NULL,
    reconciliation_reference VARCHAR(100) NOT NULL,
    review_reason VARCHAR(100),
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX agent_hosting_refunds_subscription ON agent_hosting_refunds(subscription_id, created_at DESC);
CREATE TABLE agent_hosting_refund_attempts (
    id UUID PRIMARY KEY,
    refund_id UUID NOT NULL REFERENCES agent_hosting_refunds(id),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    initiated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ready' CHECK (status IN ('ready','submitting','unknown','pending','requires_action','succeeded','failed','canceled')),
    stripe_refund_id VARCHAR(255) UNIQUE,
    first_submitted_at TIMESTAMPTZ,
    submission_count INTEGER NOT NULL DEFAULT 0,
    failure_reason VARCHAR(100),
    last_error VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(refund_id, sequence)
);
