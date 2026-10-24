-- Pending legacy or incomplete logins cannot be upgraded to frontend PKCE.
-- They must restart sign-in; established application sessions are unaffected.
DELETE FROM oauth_states
WHERE frontend_response_mode <> 'code'
   OR frontend_code_challenge IS NULL
   OR frontend_state IS NULL;

ALTER TABLE oauth_states
    DROP COLUMN frontend_response_mode,
    ALTER COLUMN frontend_code_challenge SET NOT NULL,
    ALTER COLUMN frontend_state SET NOT NULL;
