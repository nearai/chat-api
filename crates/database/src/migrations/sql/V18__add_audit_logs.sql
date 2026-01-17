-- Audit logs table with partitioning by month
-- Using BIGSERIAL for efficient time-series queries
CREATE TABLE audit_logs (
    id BIGSERIAL,

    -- Context
    organization_id UUID NOT NULL,
    workspace_id UUID,

    -- Actor information
    actor_id UUID,
    actor_type VARCHAR(50) NOT NULL DEFAULT 'user',
    actor_ip INET,
    actor_user_agent TEXT,

    -- Action details
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),

    -- Change details (JSONB for flexibility)
    changes JSONB,
    metadata JSONB,

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'success',
    error_message TEXT,

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Create initial partitions (current month and next 3 months)
-- Note: A cron job should create future partitions
CREATE TABLE audit_logs_2025_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

CREATE TABLE audit_logs_2025_02 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');

CREATE TABLE audit_logs_2025_03 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');

CREATE TABLE audit_logs_2025_04 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');

CREATE TABLE audit_logs_2025_05 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-05-01') TO ('2025-06-01');

CREATE TABLE audit_logs_2025_06 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-06-01') TO ('2025-07-01');

CREATE TABLE audit_logs_2025_07 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-07-01') TO ('2025-08-01');

CREATE TABLE audit_logs_2025_08 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-08-01') TO ('2025-09-01');

CREATE TABLE audit_logs_2025_09 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');

CREATE TABLE audit_logs_2025_10 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');

CREATE TABLE audit_logs_2025_11 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');

CREATE TABLE audit_logs_2025_12 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');

CREATE TABLE audit_logs_2026_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');

CREATE TABLE audit_logs_2026_02 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

CREATE TABLE audit_logs_2026_03 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

-- Indexes for common query patterns
CREATE INDEX idx_audit_logs_organization_id ON audit_logs(organization_id, created_at DESC);
CREATE INDEX idx_audit_logs_workspace_id ON audit_logs(workspace_id, created_at DESC) WHERE workspace_id IS NOT NULL;
CREATE INDEX idx_audit_logs_actor_id ON audit_logs(actor_id, created_at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_audit_logs_action ON audit_logs(action, created_at DESC);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id, created_at DESC);

-- BRIN index for time-series queries (more efficient than B-tree for time-ordered data)
CREATE INDEX idx_audit_logs_created_at_brin ON audit_logs USING BRIN(created_at);

-- Immutability trigger - prevent UPDATE and DELETE on audit logs
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are immutable and cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_logs_immutability
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_modification();

-- Function to create new monthly partitions
-- Should be called by a scheduled job (e.g., monthly cron)
CREATE OR REPLACE FUNCTION create_audit_log_partition(partition_date DATE)
RETURNS VOID AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    start_date := DATE_TRUNC('month', partition_date);
    end_date := start_date + INTERVAL '1 month';
    partition_name := 'audit_logs_' || TO_CHAR(start_date, 'YYYY_MM');

    EXECUTE FORMAT(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_logs
         FOR VALUES FROM (%L) TO (%L)',
        partition_name,
        start_date,
        end_date
    );
END;
$$ LANGUAGE plpgsql;

