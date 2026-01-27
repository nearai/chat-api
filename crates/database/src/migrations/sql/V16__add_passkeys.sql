-- Passkeys (WebAuthn) support
--
-- This migration adds storage for WebAuthn passkeys and short-lived WebAuthn
-- challenge state used during registration/authentication flows.
--
-- NOTE: Do NOT store raw request/response payloads. We store only the minimal
-- serialized server-side state required to safely complete the ceremony.

-- Passkeys registered to a user account
CREATE TABLE passkeys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Base64url credential ID string (browser `id`)
    credential_id TEXT NOT NULL UNIQUE,
    -- Serialized `webauthn_rs::prelude::Passkey` as JSON
    passkey JSONB NOT NULL,
    -- Optional user-facing name for UI
    nickname VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_passkeys_user_id ON passkeys(user_id);
CREATE INDEX idx_passkeys_last_used_at ON passkeys(last_used_at);

-- One-time WebAuthn ceremony state (registration/authentication)
CREATE TABLE passkey_challenges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- 'registration' | 'authentication' | 'discoverable_authentication'
    kind VARCHAR(64) NOT NULL,
    -- Present for authenticated registration flows; may be NULL for discoverable login
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    -- Serialized server-side state (PasskeyRegistration/PasskeyAuthentication/DiscoverableAuthentication)
    state JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_passkey_challenges_expires_at ON passkey_challenges(expires_at);
CREATE INDEX idx_passkey_challenges_user_id ON passkey_challenges(user_id);

