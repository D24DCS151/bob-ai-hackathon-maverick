-- Migration 002: Analyst feedback and API key tables

-- Analyst feedback on correlated threats
CREATE TABLE IF NOT EXISTS analyst_feedback (
    feedback_id     TEXT PRIMARY KEY,
    threat_id       TEXT NOT NULL REFERENCES correlated_threats(threat_id) ON DELETE CASCADE,
    analyst_id      TEXT NOT NULL,
    verdict         TEXT NOT NULL CHECK (verdict IN ('TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN', 'NEEDS_REVIEW')),
    confidence      REAL NOT NULL DEFAULT 1.0 CHECK (confidence BETWEEN 0.0 AND 1.0),
    notes           TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feedback_threat_id ON analyst_feedback (threat_id);
CREATE INDEX IF NOT EXISTS idx_feedback_verdict ON analyst_feedback (verdict);
CREATE INDEX IF NOT EXISTS idx_feedback_analyst ON analyst_feedback (analyst_id);

-- API keys for machine-to-machine authentication
CREATE TABLE IF NOT EXISTS api_keys (
    key_id          TEXT PRIMARY KEY,
    key_hash        TEXT NOT NULL UNIQUE,   -- bcrypt/SHA-256 hash of the raw key
    description     TEXT DEFAULT '',
    role            TEXT NOT NULL DEFAULT 'reader' CHECK (role IN ('reader', 'analyst', 'operator', 'admin')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    created_by      TEXT DEFAULT 'SYSTEM'
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash) WHERE NOT revoked;
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys (revoked, expires_at);

-- Enrichment cache (avoids repeated external lookups)
CREATE TABLE IF NOT EXISTS enrichment_cache (
    cache_key       TEXT PRIMARY KEY,   -- type:value (e.g. "ip:203.0.113.1")
    enrichment_type TEXT NOT NULL,
    result          JSONB NOT NULL,
    fetched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    source          TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_enrichment_expires ON enrichment_cache (expires_at);

-- Graph correlation edges (from NetworkX graph export)
CREATE TABLE IF NOT EXISTS correlation_edges (
    edge_id         TEXT PRIMARY KEY,
    threat_id       TEXT NOT NULL REFERENCES correlated_threats(threat_id) ON DELETE CASCADE,
    alert_id_a      TEXT NOT NULL,
    alert_id_b      TEXT NOT NULL,
    edge_type       TEXT NOT NULL,  -- IOC_MATCH, TEMPORAL, ASSET_OVERLAP, BEHAVIOUR
    weight          REAL NOT NULL DEFAULT 1.0,
    attributes      JSONB DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_edges_threat ON correlation_edges (threat_id);
CREATE INDEX IF NOT EXISTS idx_edges_alert_a ON correlation_edges (alert_id_a);
CREATE INDEX IF NOT EXISTS idx_edges_alert_b ON correlation_edges (alert_id_b);
