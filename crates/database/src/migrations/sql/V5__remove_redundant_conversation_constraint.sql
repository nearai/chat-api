-- Remove redundant UNIQUE(id, user_id) constraint from conversations table
-- 
-- The constraint is redundant because:
-- - 'id' is the PRIMARY KEY, so it's already unique
-- - UNIQUE(id, user_id) adds no additional uniqueness since id must be unique
-- - This constraint caused confusion with ON CONFLICT clauses
--
-- This migration cleans up the schema to match the application logic

ALTER TABLE conversations DROP CONSTRAINT IF EXISTS conversations_id_user_id_key;

