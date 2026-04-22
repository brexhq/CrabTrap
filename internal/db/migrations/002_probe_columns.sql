-- Probe evaluation audit columns.
-- Populated when the probe runner is configured; null otherwise (so operators
-- can distinguish "probes disabled" from "probes ran and returned nothing").
ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS probe_scores       JSONB,
    ADD COLUMN IF NOT EXISTS probe_tripped      TEXT,
    ADD COLUMN IF NOT EXISTS probe_aggregation  TEXT,
    ADD COLUMN IF NOT EXISTS probe_circuit_open BOOLEAN;

-- Partial index for fast "show me all probe-denied requests" queries.
CREATE INDEX IF NOT EXISTS idx_audit_log_probe_tripped
    ON audit_log(probe_tripped)
    WHERE probe_tripped IS NOT NULL AND probe_tripped <> '';
