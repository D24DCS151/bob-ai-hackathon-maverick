-- THREATICAP PostgreSQL schema initialisation
-- This script is run once at container startup.

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    schema_version  TEXT NOT NULL DEFAULT '1.0',
    source_ref      TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    source_id       TEXT NOT NULL,
    event_time      TIMESTAMPTZ NOT NULL,
    ingestion_time  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL,
    status          TEXT NOT NULL DEFAULT 'INGESTED',
    title           TEXT NOT NULL,
    description     TEXT,
    category        TEXT,
    rule_id         TEXT,
    raw_payload     JSONB,
    observables     JSONB,
    asset_context   JSONB,
    mitre_technique_ids TEXT[],
    enrichment_tags TEXT[],
    threat_actor    TEXT,
    campaign        TEXT,
    tlp             TEXT DEFAULT 'TLP:GREEN',
    dedup_hash      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_event_time ON alerts (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source_type ON alerts (source_type);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup_hash ON alerts (dedup_hash);
CREATE INDEX IF NOT EXISTS idx_alerts_campaign ON alerts (campaign);

CREATE TABLE IF NOT EXISTS correlated_threats (
    threat_id               TEXT PRIMARY KEY,
    schema_version          TEXT NOT NULL DEFAULT '1.0',
    title                   TEXT NOT NULL,
    description             TEXT,
    status                  TEXT NOT NULL DEFAULT 'OPEN',
    alert_count             INTEGER NOT NULL DEFAULT 0,
    evidence_links          JSONB,
    source_types            TEXT[],
    correlation_methods     TEXT[],
    correlation_confidence  REAL NOT NULL,
    false_positive_probability REAL NOT NULL DEFAULT 0.0,
    shared_observables      JSONB,
    all_observable_ids      TEXT[],
    affected_assets         TEXT[],
    network_segments        TEXT[],
    mitre_technique_ids     TEXT[],
    suspected_actor         TEXT,
    campaign                TEXT,
    max_severity            TEXT,
    min_event_time          TIMESTAMPTZ,
    max_event_time          TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    correlation_version     TEXT,
    audit_trail             JSONB
);

CREATE INDEX IF NOT EXISTS idx_threats_created_at ON correlated_threats (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_campaign ON correlated_threats (campaign);
CREATE INDEX IF NOT EXISTS idx_threats_actor ON correlated_threats (suspected_actor);

CREATE TABLE IF NOT EXISTS priority_scores (
    threat_id               TEXT PRIMARY KEY REFERENCES correlated_threats(threat_id),
    final_score             REAL NOT NULL,
    priority_tier           TEXT NOT NULL,
    components              JSONB,
    severity_score          REAL,
    confidence_score        REAL,
    source_reliability_score REAL,
    asset_criticality_score REAL,
    temporal_urgency_score  REAL,
    false_positive_adjustment REAL DEFAULT 0.0,
    score_explanation       TEXT,
    threshold_used          TEXT,
    scoring_version         TEXT,
    scored_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scores_tier ON priority_scores (priority_tier);
CREATE INDEX IF NOT EXISTS idx_scores_final ON priority_scores (final_score DESC);

CREATE TABLE IF NOT EXISTS bluf_reports (
    report_id               TEXT PRIMARY KEY,
    schema_version          TEXT NOT NULL DEFAULT '1.0',
    threat_id               TEXT NOT NULL REFERENCES correlated_threats(threat_id),
    report_version          INTEGER NOT NULL DEFAULT 1,
    bottom_line             TEXT NOT NULL,
    bottom_line_extended    TEXT,
    priority_tier           TEXT NOT NULL,
    priority_score          REAL NOT NULL,
    confidence_level        TEXT NOT NULL,
    tlp                     TEXT DEFAULT 'TLP:GREEN',
    key_evidence            JSONB,
    alert_count             INTEGER,
    source_types            TEXT[],
    time_window             TEXT,
    affected_assets         TEXT[],
    mitre_technique_ids     TEXT[],
    mitre_tactic_names      TEXT[],
    kill_chain_stage        TEXT,
    immediate_actions       JSONB,
    investigation_steps     JSONB,
    priority_justification  TEXT,
    score_breakdown         JSONB,
    generated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generated_by            TEXT DEFAULT 'THREATICAP-BLUF-ENGINE',
    analyst_notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_reports_threat_id ON bluf_reports (threat_id);
CREATE INDEX IF NOT EXISTS idx_reports_tier ON bluf_reports (priority_tier);
CREATE INDEX IF NOT EXISTS idx_reports_generated_at ON bluf_reports (generated_at DESC);

-- Audit log — append-only, no updates or deletes
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id        TEXT PRIMARY KEY,
    schema_version  TEXT NOT NULL DEFAULT '1.0',
    event_type      TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor           TEXT NOT NULL DEFAULT 'SYSTEM',
    component       TEXT,
    alert_id        TEXT,
    threat_id       TEXT,
    report_id       TEXT,
    summary         TEXT,
    detail          JSONB,
    previous_state  JSONB,
    new_state       JSONB,
    session_id      TEXT,
    request_id      TEXT,
    correlation_id  TEXT
);

-- Audit log: never allow UPDATE or DELETE (enforced at app layer; add row-security in production)
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_threat_id ON audit_log (threat_id);
CREATE INDEX IF NOT EXISTS idx_audit_alert_id ON audit_log (alert_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log (event_type);
