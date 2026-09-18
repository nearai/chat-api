-- `active` historically meant that a report had a recognized provider risk level. Before
-- score-policy support, UNKNOWN reports with a numeric score were therefore stored inactive
-- even though the score can now independently satisfy a high-risk policy. Preserve explicit
-- operator deactivations while reclassifying only rows that were never updated after insert.
ALTER TABLE aml_risk_reports
    ADD COLUMN active_source VARCHAR(16) NOT NULL DEFAULT 'automatic'
    CHECK (active_source IN ('automatic', 'manual'));

-- The existing update trigger advances `updated_at` whenever an administrator changes active.
-- Those rows remain inactive and are tagged for all future admin changes as well.
UPDATE aml_risk_reports
SET active_source = 'manual'
WHERE active = FALSE
  AND updated_at > created_at;

-- Only untouched, automatically-inactive legacy reports with a usable score become candidates
-- for the configured policy. The service still evaluates the current threshold before blocking.
UPDATE aml_risk_reports
SET active = TRUE
WHERE active = FALSE
  AND active_source = 'automatic'
  AND risk_level = 'UNKNOWN'
  AND score BETWEEN 1 AND 100;
