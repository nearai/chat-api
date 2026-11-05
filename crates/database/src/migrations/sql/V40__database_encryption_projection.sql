-- Dry-run conflict state survives returning pooled connections between batches.
-- Contains only internal row identifiers and HMAC search tokens, never plaintext.
CREATE TABLE database_encryption_projection (
    job_id UUID NOT NULL REFERENCES database_encryption_jobs(id) ON DELETE CASCADE,
    row_id UUID NOT NULL,
    token BYTEA NOT NULL,
    PRIMARY KEY (job_id, row_id)
);
CREATE INDEX database_encryption_projection_token
    ON database_encryption_projection(job_id, token);
