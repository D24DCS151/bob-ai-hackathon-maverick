-- Migration 001: Initial THREATICAP schema
-- Idempotent: uses IF NOT EXISTS throughout

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    schema_version  TEXT NOT NULL DEFAULT '1.0',
    source_ref      TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    source_id       TEXT NOT NULL,
    source_reliability REAL NOT NULL DEFAULT 0.8,
    event_time      TIMESTAMPTZ NOT NULL,
    ingestion_time  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL DEFAULT 0.5,
    status          TEXT NOT NULL DEFAULT 'INGESTED',
    title           TEXT NOT NULL,
    description     TEXT DEFAULT '',
    category        TEXT DEFAULT '',
    rule_id         TEXT,
    raw_payload     JSONB,
    observables     JSONB DEFAULT '[]'::jsonb,
    asset_context   JSONB DEFAULT '{}'::jsonb,
    mitre_technique_ids TEXT[] DEFAULT '{}',
    enrichment_tags TEXT[] DEFAULT '{}',
    threat_actor    TEXT,
    campaign        TEXT,
    tlp             TEXT DEFAULT 'TLP:GREEN',
    dedup_hash      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_event_time ON alerts (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source_type ON alerts (source_type);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup_hash ON alerts (dedup_hash) WHERE dedup_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alerts_campaign ON alerts (campaign) WHERE campaign IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alerts_observables ON alerts USING GIN (observables);

CREATE TABLE IF NOT EXISTS correlated_threats (
    threat_id               TEXT PRIMARY KEY,
    schema_version          TEXT NOT NULL DEFAULT '1.0',
    title                   TEXT NOT NULL,
    description             TEXT DEFAULT '',
    status                  TEXT NOT NULL DEFAULT 'OPEN',
    alert_count             INTEGER NOT NULL DEFAULT 0,
    evidence_links          JSONB DEFAULT '[]'::jsonb,
    source_types            TEXT[] DEFAULT '{}',
    correlation_methods     TEXT[] DEFAULT '{}',
    correlation_confidence  REAL NOT NULL DEFAULT 0.0,
    false_positive_probability REAL NOT NULL DEFAULT 0.0,
    shared_observables      JSONB DEFAULT '[]'::jsonb,
    all_observable_ids      TEXT[] DEFAULT '{}',
    affected_assets         TEXT[] DEFAULT '{}',
    network_segments        TEXT[] DEFAULT '{}',
    mitre_technique_ids     TEXT[] DEFAULT '{}',
    suspected_actor         TEXT,
    campaign                TEXT,
    max_severity            TEXT DEFAULT 'LOW',
    min_event_time          TIMESTAMPTZ,
    max_event_time          TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    correlation_version     TEXT DEFAULT '1.0',
    audit_trail             JSONB DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_threats_created_at ON correlated_threats (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_campaign ON correlated_threats (campaign) WHERE campaign IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_threats_actor ON correlated_threats (suspected_actor) WHERE suspected_actor IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_threats_status ON correlated_threats (status);

CREATE TABLE IF NOT EXISTS priority_scores (
    threat_id               TEXT PRIMARY KEY REFERENCES correlated_threats(threat_id) ON DELETE CASCADE,
    final_score             REAL NOT NULL,
    priority_tier           TEXT NOT NULL,
    components              JSONB DEFAULT '[]'::jsonb,
    severity_score          REAL DEFAULT 0,
    confidence_score        REAL DEFAULT 0,
    source_reliability_score REAL DEFAULT 0,
    asset_criticality_score REAL DEFAULT 0,
    temporal_urgency_score  REAL DEFAULT 0,
    false_positive_adjustment REAL DEFAULT 0,
    score_explanation       TEXT DEFAULT '',
    threshold_used          TEXT DEFAULT '',
    scoring_version         TEXT DEFAULT '1.0',
    scored_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scores_tier ON priority_scores (priority_tier);
CREATE INDEX IF NOT EXISTS idx_scores_final ON priority_scores (final_score DESC);

CREATE TABLE IF NOT EXISTS bluf_reports (
    report_id               TEXT PRIMARY KEY,
    schema_version          TEXT NOT NULL DEFAULT '1.0',
    threat_id               TEXT NOT NULL REFERENCES correlated_threats(threat_id) ON DELETE CASCADE,
    report_version          INTEGER NOT NULL DEFAULT 1,
    bottom_line             TEXT NOT NULL,
    bottom_line_extended    TEXT DEFAULT '',
    priority_tier           TEXT NOT NULL,
    priority_score          REAL NOT NULL,
    confidence_level        TEXT NOT NULL,
    tlp                     TEXT DEFAULT 'TLP:GREEN',
    key_evidence            JSONB DEFAULT '[]'::jsonb,
    alert_count             INTEGER DEFAULT 0,
    source_types            TEXT[] DEFAULT '{}',
    time_window             TEXT DEFAULT '',
    affected_assets         TEXT[] DEFAULT '{}',
    mitre_technique_ids     TEXT[] DEFAULT '{}',
    mitre_tactic_names      TEXT[] DEFAULT '{}',
    kill_chain_stage        TEXT,
    immediate_actions       JSONB DEFAULT '[]'::jsonb,
    investigation_steps     JSONB DEFAULT '[]'::jsonb,
    priority_justification  TEXT DEFAULT '',
    score_breakdown         JSONB DEFAULT '{}'::jsonb,
    generated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generated_by            TEXT DEFAULT 'THREATICAP-BLUF-ENGINE',
    analyst_notes           TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_reports_threat_id ON bluf_reports (threat_id);
CREATE INDEX IF NOT EXISTS idx_reports_tier ON bluf_reports (priority_tier);
CREATE INDEX IF NOT EXISTS idx_reports_generated_at ON bluf_reports (generated_at DESC);

-- Audit log: INSERT only. No UPDATE or DELETE granted in production.
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id        TEXT PRIMARY KEY,
    schema_version  TEXT NOT NULL DEFAULT '1.0',
    event_type      TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor           TEXT NOT NULL DEFAULT 'SYSTEM',
    component       TEXT DEFAULT '',
    alert_id        TEXT,
    threat_id       TEXT,
    report_id       TEXT,
    summary         TEXT DEFAULT '',
    detail          JSONB DEFAULT '{}'::jsonb,
    previous_state  JSONB,
    new_state       JSONB,
    session_id      TEXT,
    request_id      TEXT,
    correlation_id  TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_threat_id ON audit_log (threat_id) WHERE threat_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_alert_id ON audit_log (alert_id) WHERE alert_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log (event_type);
