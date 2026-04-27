-- Remove destructive ON DELETE CASCADE actions so account deletion can explicitly
-- choose which rows are PII/account state and which rows are audit or billing data.

-- Audit, billing, and usage rows keep their user_id value for reconciliation even
-- after the users row is removed, so they intentionally no longer have a users FK.
ALTER TABLE IF EXISTS agent_instances DROP CONSTRAINT IF EXISTS agent_instances_user_id_fkey;
ALTER TABLE IF EXISTS agent_usage_log DROP CONSTRAINT IF EXISTS agent_usage_log_user_id_fkey;
ALTER TABLE IF EXISTS subscriptions DROP CONSTRAINT IF EXISTS subscriptions_user_id_fkey;
ALTER TABLE IF EXISTS user_usage_event DROP CONSTRAINT IF EXISTS user_usage_event_user_id_fkey;
ALTER TABLE IF EXISTS credit_transactions DROP CONSTRAINT IF EXISTS credit_transactions_user_id_fkey;

-- Account-owned rows are deleted explicitly by the account deletion flow.
ALTER TABLE IF EXISTS oauth_accounts DROP CONSTRAINT IF EXISTS oauth_accounts_user_id_fkey;
ALTER TABLE IF EXISTS oauth_accounts
    ADD CONSTRAINT oauth_accounts_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS oauth_tokens DROP CONSTRAINT IF EXISTS oauth_tokens_user_id_fkey;
ALTER TABLE IF EXISTS oauth_tokens
    ADD CONSTRAINT oauth_tokens_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS sessions DROP CONSTRAINT IF EXISTS sessions_user_id_fkey;
ALTER TABLE IF EXISTS sessions
    ADD CONSTRAINT sessions_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS conversations DROP CONSTRAINT IF EXISTS conversations_user_id_fkey;
ALTER TABLE IF EXISTS conversations
    ADD CONSTRAINT conversations_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS user_settings DROP CONSTRAINT IF EXISTS user_settings_user_id_fkey;
ALTER TABLE IF EXISTS user_settings
    ADD CONSTRAINT user_settings_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS files DROP CONSTRAINT IF EXISTS files_user_id_fkey;
ALTER TABLE IF EXISTS files
    ADD CONSTRAINT files_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS user_activity_log DROP CONSTRAINT IF EXISTS user_activity_log_user_id_fkey;
ALTER TABLE IF EXISTS user_activity_log
    ADD CONSTRAINT user_activity_log_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS user_bans DROP CONSTRAINT IF EXISTS user_bans_user_id_fkey;
ALTER TABLE IF EXISTS user_bans
    ADD CONSTRAINT user_bans_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS stripe_customers DROP CONSTRAINT IF EXISTS stripe_customers_user_id_fkey;
ALTER TABLE IF EXISTS stripe_customers
    ADD CONSTRAINT stripe_customers_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS user_credits DROP CONSTRAINT IF EXISTS user_credits_user_id_fkey;
ALTER TABLE IF EXISTS user_credits
    ADD CONSTRAINT user_credits_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS user_passkey_credentials DROP CONSTRAINT IF EXISTS user_passkey_credentials_user_id_fkey;
ALTER TABLE IF EXISTS user_passkey_credentials
    ADD CONSTRAINT user_passkey_credentials_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS agent_api_keys DROP CONSTRAINT IF EXISTS agent_api_keys_user_id_fkey;
ALTER TABLE IF EXISTS agent_api_keys
    ADD CONSTRAINT agent_api_keys_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS conversation_share_groups DROP CONSTRAINT IF EXISTS conversation_share_groups_owner_user_id_fkey;
ALTER TABLE IF EXISTS conversation_share_groups
    ADD CONSTRAINT conversation_share_groups_owner_user_id_fkey
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS conversation_shares DROP CONSTRAINT IF EXISTS conversation_shares_owner_user_id_fkey;
ALTER TABLE IF EXISTS conversation_shares
    ADD CONSTRAINT conversation_shares_owner_user_id_fkey
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE RESTRICT;

-- Non-user cascades are also removed. Nullable child links use SET NULL where
-- that preserves history without violating table checks; otherwise RESTRICT.
ALTER TABLE IF EXISTS agent_api_keys DROP CONSTRAINT IF EXISTS agent_api_keys_instance_id_fkey;
ALTER TABLE IF EXISTS agent_api_keys
    ADD CONSTRAINT agent_api_keys_instance_id_fkey
    FOREIGN KEY (instance_id) REFERENCES agent_instances(id) ON DELETE SET NULL;

ALTER TABLE IF EXISTS conversation_share_group_members DROP CONSTRAINT IF EXISTS conversation_share_group_members_group_id_fkey;
ALTER TABLE IF EXISTS conversation_share_group_members
    ADD CONSTRAINT conversation_share_group_members_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES conversation_share_groups(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS conversation_shares DROP CONSTRAINT IF EXISTS conversation_shares_conversation_id_fkey;
ALTER TABLE IF EXISTS conversation_shares
    ADD CONSTRAINT conversation_shares_conversation_id_fkey
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS conversation_shares DROP CONSTRAINT IF EXISTS conversation_shares_group_id_fkey;
ALTER TABLE IF EXISTS conversation_shares
    ADD CONSTRAINT conversation_shares_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES conversation_share_groups(id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS agent_instance_status_history DROP CONSTRAINT IF EXISTS agent_instance_status_history_instance_id_fkey;
ALTER TABLE IF EXISTS agent_instance_status_history
    ADD CONSTRAINT agent_instance_status_history_instance_id_fkey
    FOREIGN KEY (instance_id) REFERENCES agent_instances(id) ON DELETE RESTRICT;
