-- UUID identity lets the provider verifier use the existing field encryption
-- envelope and inventory/backfill paths. Keep the old state primary key intact.
ALTER TABLE oauth_states
    ADD COLUMN id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    ADD COLUMN provider_code_verifier TEXT;

-- Older instances can still insert states while rolling out. New instances
-- reject NULL verifiers at callback time; pending logins must restart.
