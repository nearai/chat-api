-- Table for mapping chat-api users to Stripe customers
CREATE TABLE stripe_customers (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    customer_id VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Trigger for updating updated_at timestamp on stripe_customers
CREATE TRIGGER update_stripe_customers_updated_at
    BEFORE UPDATE ON stripe_customers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Table for storing subscription records from Stripe
CREATE TABLE subscriptions (
    subscription_id VARCHAR(255) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    customer_id VARCHAR(255) NOT NULL,
    price_id VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,
    current_period_end TIMESTAMPTZ NOT NULL,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for efficient user subscription lookups
CREATE INDEX idx_subscriptions_user_id ON subscriptions(user_id);

-- Index for efficient customer subscription lookups
CREATE INDEX idx_subscriptions_customer_id ON subscriptions(customer_id);

-- Index for efficient status filtering
CREATE INDEX idx_subscriptions_status ON subscriptions(status);

-- Trigger for updating updated_at timestamp on subscriptions
CREATE TRIGGER update_subscriptions_updated_at
    BEFORE UPDATE ON subscriptions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Table for storing payment webhook events (generic, future-proof)
CREATE TABLE payment_webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider VARCHAR(50) NOT NULL,
    event_id VARCHAR(255) NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, event_id)
);

-- Index for efficient provider/event_id lookups
CREATE INDEX idx_payment_webhooks_provider_event ON payment_webhooks(provider, event_id);
