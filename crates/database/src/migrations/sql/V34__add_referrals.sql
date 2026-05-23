-- Referral identity and reward tracking.
-- Referral rewards are not part of user_credits until they are granted.

ALTER TABLE users
ADD COLUMN referral_code VARCHAR(16);

CREATE UNIQUE INDEX idx_users_referral_code
    ON users(referral_code)
    WHERE referral_code IS NOT NULL;

ALTER TABLE credit_transactions
ADD COLUMN source VARCHAR(50),
ADD COLUMN metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE UNIQUE INDEX idx_credit_transactions_source_ref
    ON credit_transactions(source, reference_id)
    WHERE source IS NOT NULL AND reference_id IS NOT NULL;

CREATE TABLE referrals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    inviter_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invitee_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    referral_code_used VARCHAR(16) NOT NULL,
    reward_trigger_policy VARCHAR(50) NOT NULL CHECK (
        reward_trigger_policy IN ('invitee_registered', 'invitee_first_active_subscription')
    ),
    invitee_reward_amount_nano_usd BIGINT NOT NULL CHECK (invitee_reward_amount_nano_usd > 0),
    invitee_reward_credit_transaction_id UUID REFERENCES credit_transactions(id),
    invitee_reward_granted_at TIMESTAMPTZ,
    inviter_reward_amount_nano_usd BIGINT NOT NULL CHECK (inviter_reward_amount_nano_usd > 0),
    inviter_reward_credit_transaction_id UUID REFERENCES credit_transactions(id),
    inviter_reward_granted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (inviter_user_id <> invitee_user_id)
);

CREATE INDEX idx_referrals_inviter_user_id ON referrals(inviter_user_id);
CREATE INDEX idx_referrals_invitee_user_id ON referrals(invitee_user_id);

ALTER TABLE oauth_states
ADD COLUMN referral_code VARCHAR(16);
