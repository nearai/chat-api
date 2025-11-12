-- Remove title column from conversations table
-- The API now only tracks conversation IDs per user
-- and fetches conversation details from OpenAI API on demand

ALTER TABLE conversations DROP COLUMN IF EXISTS title;

