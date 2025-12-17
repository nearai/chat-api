-- Globals table for storing application-wide JSONB configuration
-- Similar to models table, but keyed by a logical string key
CREATE TABLE globals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key TEXT NOT NULL UNIQUE,
    value JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Trigger for updating updated_at timestamp
CREATE TRIGGER update_globals_updated_at
    BEFORE UPDATE ON globals
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();


