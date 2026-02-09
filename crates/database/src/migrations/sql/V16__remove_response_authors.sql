-- Remove response_authors table and index
-- Response author tracking is now handled by cloud-api (PR #375)

DROP INDEX IF EXISTS idx_response_authors_conversation;
DROP TABLE IF EXISTS response_authors;
