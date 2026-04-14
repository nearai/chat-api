CREATE TABLE email_verification_challenges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL,
    code_mac TEXT NOT NULL,
    ip_address INET,
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'sent', 'failed', 'consumed', 'invalidated')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    provider_message_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_email_verification_challenges_email_created_at
    ON email_verification_challenges(email, created_at DESC);

CREATE INDEX idx_email_verification_challenges_ip_created_at
    ON email_verification_challenges(ip_address, created_at DESC);

CREATE INDEX idx_email_verification_challenges_email_status_expires_at
    ON email_verification_challenges(email, status, expires_at DESC);
