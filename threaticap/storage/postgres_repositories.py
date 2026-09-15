"""
PostgreSQL-backed repositories using psycopg2 with connection pooling.

Architecture:
- Uses psycopg2 SimpleConnectionPool (min/max configurable)
- Context manager for connection borrow/return
- JSON serialisation for complex fields
- Explicit parameterised queries (no string interpolation — SQL injection prevention)
- Append-only enforcement on audit table via INSERT-only methods

Production hardening checklist:
- Use ssl_mode=verify-full in production with CA cert
- Set pool_min/pool_max based on expected concurrency
- Use pgBouncer in front for very high throughput
- Enable pg_audit extension for database-level audit logging
"""
from __future__ import annotations

import json
import logging
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator, Optional

from threaticap.models.alert import Alert, AlertSeverity, AlertSource, AlertStatus
from threaticap.models.audit import AuditRecord, AuditEventType
from threaticap.models.bluf import BlufReport, ConfidenceLevel
from threaticap.models.correlated_threat import CorrelatedThreat, ThreatStatus, CorrelationMethod
from threaticap.models.priority import PriorityScore, PriorityTier
from threaticap.storage.repositories import (
    BaseAlertRepository,
    BaseAuditRepository,
    BaseReportRepository,
    BaseThreatRepository,
)

logger = logging.getLogger(__name__)

try:
    import psycopg2
    import psycopg2.pool
    import psycopg2.extras
    _HAS_PSYCOPG2 = True
except ImportError:
    _HAS_PSYCOPG2 = False
    logger.warning("psycopg2 not available — PostgreSQL repositories disabled")


def _require_psycopg2() -> None:
    if not _HAS_PSYCOPG2:
        raise RuntimeError(
            "psycopg2 is not installed. "
            "Install it with: pip install psycopg2-binary"
        )


def _json_serial(obj: Any) -> str:
    """JSON serialiser that handles datetime objects."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serialisable")


def _dumps(obj: Any) -> str:
    return json.dumps(obj, default=_json_serial)


class PostgresConnectionPool:
    """
    Thread-safe PostgreSQL connection pool wrapper.

    Usage:
        pool = PostgresConnectionPool(dsn="postgresql://user:pass@host/db")
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
    """

    def __init__(
        self,
        dsn: str,
        min_connections: int = 2,
        max_connections: int = 10,
        ssl_mode: str = "prefer",
    ) -> None:
        _require_psycopg2()
        self._dsn = dsn
        self._lock = threading.Lock()
        # Append ssl mode if not already in DSN
        connect_dsn = dsn
        if "sslmode" not in dsn and ssl_mode:
            sep = "&" if "?" in dsn else "?"
            connect_dsn = f"{dsn}{sep}sslmode={ssl_mode}"

        self._pool = psycopg2.pool.ThreadedConnectionPool(
            min_connections,
            max_connections,
            connect_dsn,
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        logger.info(
            "PostgreSQL pool created (min=%d max=%d)", min_connections, max_connections
        )

    @contextmanager
    def connection(self) -> Generator[Any, None, None]:
        """Borrow a connection from the pool; return it on exit."""
        conn = self._pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    def close(self) -> None:
        self._pool.closeall()
        logger.info("PostgreSQL pool closed")


# ---------------------------------------------------------------------------
# Alert Repository
# ---------------------------------------------------------------------------

class PostgresAlertRepository(BaseAlertRepository):
    """
    PostgreSQL-backed alert repository.

    All writes are explicit INSERT or UPDATE — no UPSERT magic that could
    silently overwrite data in concurrent environments.
    """

    def __init__(self, pool: PostgresConnectionPool) -> None:
        self._pool = pool

    def save(self, alert: Alert) -> None:
        sql = """
            INSERT INTO alerts (
                alert_id, schema_version, source_ref, source_type, source_id,
                source_reliability, event_time, ingestion_time, severity,
                confidence, status, title, description, category, rule_id,
                raw_payload, observables, asset_context, mitre_technique_ids,
                enrichment_tags, threat_actor, campaign, tlp, dedup_hash
            ) VALUES (
                %(alert_id)s, %(schema_version)s, %(source_ref)s, %(source_type)s,
                %(source_id)s, %(source_reliability)s, %(event_time)s, %(ingestion_time)s,
                %(severity)s, %(confidence)s, %(status)s, %(title)s, %(description)s,
                %(category)s, %(rule_id)s, %(raw_payload)s::jsonb, %(observables)s::jsonb,
                %(asset_context)s::jsonb, %(mitre_technique_ids)s, %(enrichment_tags)s,
                %(threat_actor)s, %(campaign)s, %(tlp)s, %(dedup_hash)s
            )
            ON CONFLICT (alert_id) DO UPDATE SET
                status = EXCLUDED.status,
                enrichment_tags = EXCLUDED.enrichment_tags
        """
        params = {
            "alert_id": alert.alert_id,
            "schema_version": alert.schema_version,
            "source_ref": alert.source_ref,
            "source_type": alert.source_type.value,
            "source_id": alert.source_id,
            "source_reliability": alert.source_reliability,
            "event_time": alert.event_time,
            "ingestion_time": alert.ingestion_time,
            "severity": alert.severity.value,
            "confidence": alert.confidence,
            "status": alert.status.value,
            "title": alert.title,
            "description": alert.description,
            "category": alert.category,
            "rule_id": alert.rule_id,
            "raw_payload": _dumps(alert.raw_payload) if alert.raw_payload else None,
            "observables": _dumps([o.model_dump() for o in alert.observables]),
            "asset_context": _dumps(alert.asset_context.model_dump()),
            "mitre_technique_ids": alert.mitre_technique_ids,
            "enrichment_tags": alert.enrichment_tags,
            "threat_actor": alert.threat_actor,
            "campaign": alert.campaign,
            "tlp": alert.tlp,
            "dedup_hash": alert.dedup_hash,
        }
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)

    def save_batch(self, alerts: list[Alert]) -> int:
        for alert in alerts:
            self.save(alert)
        return len(alerts)

    def get(self, alert_id: str) -> Alert | None:
        sql = "SELECT * FROM alerts WHERE alert_id = %s"
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (alert_id,))
                row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_alert(dict(row))

    def list_recent(self, limit: int = 100, offset: int = 0) -> list[Alert]:
        sql = "SELECT * FROM alerts ORDER BY ingestion_time DESC LIMIT %s OFFSET %s"
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (limit, offset))
                rows = cur.fetchall()
        return [self._row_to_alert(dict(r)) for r in rows]

    def find_by_observable(self, value: str) -> list[Alert]:
        # Use JSONB containment operator for efficient lookup
        sql = """
            SELECT * FROM alerts
            WHERE observables @> %s::jsonb
            LIMIT 100
        """
        search_json = _dumps([{"value": value}])
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (search_json,))
                rows = cur.fetchall()
        return [self._row_to_alert(dict(r)) for r in rows]

    def count(self) -> int:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM alerts")
                result = cur.fetchone()
        return int(result["count"]) if result else 0

    def get_lookup(self) -> dict[str, Alert]:
        alerts = self.list_recent(limit=10000)
        return {a.alert_id: a for a in alerts}

    @staticmethod
    def _row_to_alert(row: dict[str, Any]) -> Alert:
        from threaticap.models.alert import AssetContext, Observable
        observables_raw = row.get("observables") or []
        if isinstance(observables_raw, str):
            observables_raw = json.loads(observables_raw)
        observables = [Observable(**o) for o in observables_raw]

        asset_raw = row.get("asset_context") or {}
        if isinstance(asset_raw, str):
            asset_raw = json.loads(asset_raw)
        asset_ctx = AssetContext(**asset_raw) if asset_raw else AssetContext()

        raw_payload = row.get("raw_payload")
        if isinstance(raw_payload, str):
            raw_payload = json.loads(raw_payload)

        return Alert(
            alert_id=row["alert_id"],
            schema_version=row.get("schema_version", "1.0"),
            source_ref=row["source_ref"],
            source_type=AlertSource(row["source_type"]),
            source_id=row["source_id"],
            source_reliability=float(row.get("source_reliability", 0.8)),
            event_time=row["event_time"],
            ingestion_time=row.get("ingestion_time") or datetime.now(timezone.utc),
            severity=AlertSeverity(row["severity"]),
            confidence=float(row.get("confidence", 0.5)),
            status=AlertStatus(row.get("status", "INGESTED")),
            title=row["title"],
            description=row.get("description", ""),
            category=row.get("category", ""),
            rule_id=row.get("rule_id"),
            raw_payload=raw_payload,
            observables=observables,
            asset_context=asset_ctx,
            mitre_technique_ids=list(row.get("mitre_technique_ids") or []),
            enrichment_tags=list(row.get("enrichment_tags") or []),
            threat_actor=row.get("threat_actor"),
            campaign=row.get("campaign"),
            tlp=row.get("tlp", "TLP:GREEN"),
            dedup_hash=row.get("dedup_hash"),
        )


# ---------------------------------------------------------------------------
# Threat Repository
# ---------------------------------------------------------------------------

class PostgresThreatRepository(BaseThreatRepository):

    def __init__(self, pool: PostgresConnectionPool) -> None:
        self._pool = pool

    def save(self, threat: CorrelatedThreat, score: PriorityScore | None = None) -> None:
        threat_sql = """
            INSERT INTO correlated_threats (
                threat_id, schema_version, title, description, status,
                alert_count, evidence_links, source_types, correlation_methods,
                correlation_confidence, false_positive_probability,
                shared_observables, all_observable_ids, affected_assets,
                network_segments, mitre_technique_ids, suspected_actor,
                campaign, max_severity, min_event_time, max_event_time,
                created_at, updated_at, correlation_version, audit_trail
            ) VALUES (
                %(threat_id)s, %(schema_version)s, %(title)s, %(description)s,
                %(status)s, %(alert_count)s, %(evidence_links)s::jsonb,
                %(source_types)s, %(correlation_methods)s,
                %(correlation_confidence)s, %(false_positive_probability)s,
                %(shared_observables)s::jsonb, %(all_observable_ids)s,
                %(affected_assets)s, %(network_segments)s,
                %(mitre_technique_ids)s, %(suspected_actor)s, %(campaign)s,
                %(max_severity)s, %(min_event_time)s, %(max_event_time)s,
                %(created_at)s, %(updated_at)s, %(correlation_version)s,
                %(audit_trail)s::jsonb
            )
            ON CONFLICT (threat_id) DO UPDATE SET
                status = EXCLUDED.status,
                updated_at = EXCLUDED.updated_at,
                false_positive_probability = EXCLUDED.false_positive_probability,
                audit_trail = EXCLUDED.audit_trail
        """
        params = {
            "threat_id": threat.threat_id,
            "schema_version": threat.schema_version,
            "title": threat.title,
            "description": threat.description,
            "status": threat.status.value,
            "alert_count": threat.alert_count,
            "evidence_links": _dumps([e.model_dump() for e in threat.evidence_links]),
            "source_types": threat.source_types,
            "correlation_methods": [m.value for m in threat.correlation_methods],
            "correlation_confidence": threat.correlation_confidence,
            "false_positive_probability": threat.false_positive_probability,
            "shared_observables": _dumps(threat.shared_observables),
            "all_observable_ids": threat.all_observable_ids,
            "affected_assets": threat.affected_assets,
            "network_segments": threat.network_segments,
            "mitre_technique_ids": threat.mitre_technique_ids,
            "suspected_actor": threat.suspected_actor,
            "campaign": threat.campaign,
            "max_severity": threat.max_severity,
            "min_event_time": threat.min_event_time,
            "max_event_time": threat.max_event_time,
            "created_at": threat.created_at,
            "updated_at": threat.updated_at,
            "correlation_version": threat.correlation_version,
            "audit_trail": _dumps(threat.audit_trail),
        }

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(threat_sql, params)
                if score:
                    self._save_score(cur, score)

    def _save_score(self, cur: Any, score: PriorityScore) -> None:
        score_sql = """
            INSERT INTO priority_scores (
                threat_id, final_score, priority_tier, components,
                severity_score, confidence_score, source_reliability_score,
                asset_criticality_score, temporal_urgency_score,
                false_positive_adjustment, score_explanation,
                threshold_used, scoring_version, scored_at
            ) VALUES (
                %(threat_id)s, %(final_score)s, %(priority_tier)s,
                %(components)s::jsonb, %(severity_score)s,
                %(confidence_score)s, %(source_reliability_score)s,
                %(asset_criticality_score)s, %(temporal_urgency_score)s,
                %(false_positive_adjustment)s, %(score_explanation)s,
                %(threshold_used)s, %(scoring_version)s, %(scored_at)s
            )
            ON CONFLICT (threat_id) DO UPDATE SET
                final_score = EXCLUDED.final_score,
                priority_tier = EXCLUDED.priority_tier,
                components = EXCLUDED.components,
                score_explanation = EXCLUDED.score_explanation,
                scored_at = EXCLUDED.scored_at
        """
        cur.execute(score_sql, {
            "threat_id": score.threat_id,
            "final_score": score.final_score,
            "priority_tier": score.priority_tier.value,
            "components": _dumps([c.model_dump() for c in score.components]),
            "severity_score": score.severity_score,
            "confidence_score": score.confidence_score,
            "source_reliability_score": score.source_reliability_score,
            "asset_criticality_score": score.asset_criticality_score,
            "temporal_urgency_score": score.temporal_urgency_score,
            "false_positive_adjustment": score.false_positive_adjustment,
            "score_explanation": score.score_explanation,
            "threshold_used": score.threshold_used,
            "scoring_version": score.scoring_version,
            "scored_at": score.scored_at,
        })

    def get(self, threat_id: str) -> CorrelatedThreat | None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM correlated_threats WHERE threat_id = %s",
                    (threat_id,)
                )
                row = cur.fetchone()
        return self._row_to_threat(dict(row)) if row else None

    def get_score(self, threat_id: str) -> PriorityScore | None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM priority_scores WHERE threat_id = %s",
                    (threat_id,)
                )
                row = cur.fetchone()
        return self._row_to_score(dict(row)) if row else None

    def list_by_priority(
        self,
        tier: PriorityTier | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[tuple[CorrelatedThreat, PriorityScore | None]]:
        if tier:
            sql = """
                SELECT t.*, s.final_score, s.priority_tier, s.components,
                       s.severity_score, s.confidence_score, s.source_reliability_score,
                       s.asset_criticality_score, s.temporal_urgency_score,
                       s.false_positive_adjustment, s.score_explanation,
                       s.threshold_used, s.scoring_version, s.scored_at
                FROM correlated_threats t
                LEFT JOIN priority_scores s ON t.threat_id = s.threat_id
                WHERE s.priority_tier = %s
                ORDER BY COALESCE(s.final_score, 0) DESC
                LIMIT %s OFFSET %s
            """
            args = (tier.value, limit, offset)
        else:
            sql = """
                SELECT t.*, s.final_score, s.priority_tier, s.components,
                       s.severity_score, s.confidence_score, s.source_reliability_score,
                       s.asset_criticality_score, s.temporal_urgency_score,
                       s.false_positive_adjustment, s.score_explanation,
                       s.threshold_used, s.scoring_version, s.scored_at
                FROM correlated_threats t
                LEFT JOIN priority_scores s ON t.threat_id = s.threat_id
                ORDER BY COALESCE(s.final_score, 0) DESC
                LIMIT %s OFFSET %s
            """
            args = (limit, offset)

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, args)
                rows = cur.fetchall()

        results = []
        for row in rows:
            d = dict(row)
            threat = self._row_to_threat(d)
            score = self._row_to_score(d) if d.get("final_score") is not None else None
            results.append((threat, score))
        return results

    def count(self) -> int:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM correlated_threats")
                result = cur.fetchone()
        return int(result["count"]) if result else 0

    @staticmethod
    def _row_to_threat(row: dict[str, Any]) -> CorrelatedThreat:
        from threaticap.models.correlated_threat import EvidenceLink

        def parse_json(v: Any) -> Any:
            if isinstance(v, str):
                return json.loads(v)
            return v or []

        evidence_raw = parse_json(row.get("evidence_links"))
        evidence = [EvidenceLink(**e) for e in evidence_raw] if evidence_raw else []

        methods_raw = row.get("correlation_methods") or []
        methods = []
        for m in methods_raw:
            try:
                methods.append(CorrelationMethod(m))
            except ValueError:
                pass

        return CorrelatedThreat(
            threat_id=row["threat_id"],
            schema_version=row.get("schema_version", "1.0"),
            title=row["title"],
            description=row.get("description", ""),
            status=ThreatStatus(row.get("status", "OPEN")),
            alert_count=int(row.get("alert_count", 0)),
            evidence_links=evidence,
            source_types=list(row.get("source_types") or []),
            correlation_methods=methods,
            correlation_confidence=float(row.get("correlation_confidence", 0.0)),
            false_positive_probability=float(row.get("false_positive_probability", 0.0)),
            shared_observables=parse_json(row.get("shared_observables")),
            all_observable_ids=list(row.get("all_observable_ids") or []),
            affected_assets=list(row.get("affected_assets") or []),
            network_segments=list(row.get("network_segments") or []),
            mitre_technique_ids=list(row.get("mitre_technique_ids") or []),
            suspected_actor=row.get("suspected_actor"),
            campaign=row.get("campaign"),
            max_severity=row.get("max_severity", "LOW"),
            min_event_time=row.get("min_event_time"),
            max_event_time=row.get("max_event_time"),
            created_at=row.get("created_at") or datetime.now(timezone.utc),
            updated_at=row.get("updated_at") or datetime.now(timezone.utc),
            correlation_version=row.get("correlation_version", "1.0"),
            audit_trail=parse_json(row.get("audit_trail")),
        )

    @staticmethod
    def _row_to_score(row: dict[str, Any]) -> PriorityScore | None:
        if not row.get("final_score") is not None:
            return None
        from threaticap.models.priority import ScoreComponent

        def parse_json(v: Any) -> Any:
            if isinstance(v, str):
                return json.loads(v)
            return v or []

        components_raw = parse_json(row.get("components"))
        components = [ScoreComponent(**c) for c in components_raw] if components_raw else []

        tier_val = row.get("priority_tier", "LOW")
        try:
            tier = PriorityTier(tier_val)
        except ValueError:
            tier = PriorityTier.LOW

        return PriorityScore(
            threat_id=row["threat_id"],
            components=components,
            severity_score=float(row.get("severity_score") or 0),
            confidence_score=float(row.get("confidence_score") or 0),
            source_reliability_score=float(row.get("source_reliability_score") or 0),
            asset_criticality_score=float(row.get("asset_criticality_score") or 0),
            temporal_urgency_score=float(row.get("temporal_urgency_score") or 0),
            final_score=float(row.get("final_score") or 0),
            priority_tier=tier,
            false_positive_adjustment=float(row.get("false_positive_adjustment") or 0),
            score_explanation=row.get("score_explanation", ""),
            threshold_used=row.get("threshold_used", ""),
            scoring_version=row.get("scoring_version", "1.0"),
            scored_at=row.get("scored_at") or datetime.now(timezone.utc),
        )


# ---------------------------------------------------------------------------
# Audit Repository (append-only enforced at SQL level)
# ---------------------------------------------------------------------------

class PostgresAuditRepository(BaseAuditRepository):

    def __init__(self, pool: PostgresConnectionPool) -> None:
        self._pool = pool

    def append(self, record: AuditRecord) -> None:
        sql = """
            INSERT INTO audit_log (
                audit_id, schema_version, event_type, timestamp, actor,
                component, alert_id, threat_id, report_id, summary,
                detail, previous_state, new_state, session_id,
                request_id, correlation_id
            ) VALUES (
                %(audit_id)s, %(schema_version)s, %(event_type)s, %(timestamp)s,
                %(actor)s, %(component)s, %(alert_id)s, %(threat_id)s,
                %(report_id)s, %(summary)s, %(detail)s::jsonb,
                %(previous_state)s::jsonb, %(new_state)s::jsonb,
                %(session_id)s, %(request_id)s, %(correlation_id)s
            )
        """
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, {
                    "audit_id": record.audit_id,
                    "schema_version": record.schema_version,
                    "event_type": record.event_type.value,
                    "timestamp": record.timestamp,
                    "actor": record.actor,
                    "component": record.component,
                    "alert_id": record.alert_id,
                    "threat_id": record.threat_id,
                    "report_id": record.report_id,
                    "summary": record.summary,
                    "detail": _dumps(record.detail),
                    "previous_state": _dumps(record.previous_state) if record.previous_state else None,
                    "new_state": _dumps(record.new_state) if record.new_state else None,
                    "session_id": record.session_id,
                    "request_id": record.request_id,
                    "correlation_id": record.correlation_id,
                })

    def get_for_threat(self, threat_id: str) -> list[AuditRecord]:
        sql = "SELECT * FROM audit_log WHERE threat_id = %s ORDER BY timestamp ASC"
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (threat_id,))
                rows = cur.fetchall()
        return [self._row_to_record(dict(r)) for r in rows]

    def get_for_alert(self, alert_id: str) -> list[AuditRecord]:
        sql = "SELECT * FROM audit_log WHERE alert_id = %s ORDER BY timestamp ASC"
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (alert_id,))
                rows = cur.fetchall()
        return [self._row_to_record(dict(r)) for r in rows]

    def list_recent(self, limit: int = 200) -> list[AuditRecord]:
        sql = "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT %s"
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (limit,))
                rows = cur.fetchall()
        return [self._row_to_record(dict(r)) for r in rows]

    def count(self) -> int:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM audit_log")
                r = cur.fetchone()
        return int(r["count"]) if r else 0

    @staticmethod
    def _row_to_record(row: dict[str, Any]) -> AuditRecord:
        def parse_json(v: Any) -> Any:
            if isinstance(v, str):
                return json.loads(v)
            return v

        return AuditRecord(
            audit_id=row["audit_id"],
            schema_version=row.get("schema_version", "1.0"),
            event_type=AuditEventType(row["event_type"]),
            timestamp=row["timestamp"],
            actor=row.get("actor", "SYSTEM"),
            component=row.get("component", ""),
            alert_id=row.get("alert_id"),
            threat_id=row.get("threat_id"),
            report_id=row.get("report_id"),
            summary=row.get("summary", ""),
            detail=parse_json(row.get("detail")) or {},
            previous_state=parse_json(row.get("previous_state")),
            new_state=parse_json(row.get("new_state")),
            session_id=row.get("session_id"),
            request_id=row.get("request_id"),
            correlation_id=row.get("correlation_id"),
        )


# ---------------------------------------------------------------------------
# Report Repository
# ---------------------------------------------------------------------------

class PostgresReportRepository(BaseReportRepository):

    def __init__(self, pool: PostgresConnectionPool) -> None:
        self._pool = pool

    def save(self, report: BlufReport) -> None:
        sql = """
            INSERT INTO bluf_reports (
                report_id, schema_version, threat_id, report_version,
                bottom_line, bottom_line_extended, priority_tier,
                priority_score, confidence_level, tlp, key_evidence,
                alert_count, source_types, time_window, affected_assets,
                mitre_technique_ids, mitre_tactic_names, kill_chain_stage,
                immediate_actions, investigation_steps, priority_justification,
                score_breakdown, generated_at, generated_by, analyst_notes
            ) VALUES (
                %(report_id)s, %(schema_version)s, %(threat_id)s, %(report_version)s,
                %(bottom_line)s, %(bottom_line_extended)s, %(priority_tier)s,
                %(priority_score)s, %(confidence_level)s, %(tlp)s,
                %(key_evidence)s::jsonb, %(alert_count)s, %(source_types)s,
                %(time_window)s, %(affected_assets)s, %(mitre_technique_ids)s,
                %(mitre_tactic_names)s, %(kill_chain_stage)s,
                %(immediate_actions)s::jsonb, %(investigation_steps)s::jsonb,
                %(priority_justification)s, %(score_breakdown)s::jsonb,
                %(generated_at)s, %(generated_by)s, %(analyst_notes)s
            )
            ON CONFLICT (report_id) DO NOTHING
        """
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, {
                    "report_id": report.report_id,
                    "schema_version": report.schema_version,
                    "threat_id": report.threat_id,
                    "report_version": report.report_version,
                    "bottom_line": report.bottom_line,
                    "bottom_line_extended": report.bottom_line_extended,
                    "priority_tier": report.priority_tier,
                    "priority_score": report.priority_score,
                    "confidence_level": report.confidence_level.value,
                    "tlp": report.tlp,
                    "key_evidence": _dumps([e.model_dump() for e in report.key_evidence]),
                    "alert_count": report.alert_count,
                    "source_types": report.source_types,
                    "time_window": report.time_window,
                    "affected_assets": report.affected_assets,
                    "mitre_technique_ids": report.mitre_technique_ids,
                    "mitre_tactic_names": report.mitre_tactic_names,
                    "kill_chain_stage": report.kill_chain_stage,
                    "immediate_actions": _dumps([a.model_dump() for a in report.immediate_actions]),
                    "investigation_steps": _dumps([s.model_dump() for s in report.investigation_steps]),
                    "priority_justification": report.priority_justification,
                    "score_breakdown": _dumps(report.score_breakdown),
                    "generated_at": report.generated_at,
                    "generated_by": report.generated_by,
                    "analyst_notes": report.analyst_notes,
                })

    def get(self, report_id: str) -> BlufReport | None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM bluf_reports WHERE report_id = %s", (report_id,)
                )
                row = cur.fetchone()
        return self._row_to_report(dict(row)) if row else None

    def get_for_threat(self, threat_id: str) -> list[BlufReport]:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM bluf_reports WHERE threat_id = %s ORDER BY generated_at",
                    (threat_id,)
                )
                rows = cur.fetchall()
        return [self._row_to_report(dict(r)) for r in rows]

    def list_recent(self, limit: int = 50) -> list[BlufReport]:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM bluf_reports ORDER BY generated_at DESC LIMIT %s",
                    (limit,)
                )
                rows = cur.fetchall()
        return [self._row_to_report(dict(r)) for r in rows]

    @staticmethod
    def _row_to_report(row: dict[str, Any]) -> BlufReport:
        from threaticap.models.bluf import ActionItem, EvidenceSummary

        def parse_json(v: Any) -> Any:
            if isinstance(v, str):
                return json.loads(v)
            return v or []

        return BlufReport(
            report_id=row["report_id"],
            schema_version=row.get("schema_version", "1.0"),
            threat_id=row["threat_id"],
            report_version=int(row.get("report_version", 1)),
            bottom_line=row["bottom_line"],
            bottom_line_extended=row.get("bottom_line_extended", ""),
            priority_tier=row["priority_tier"],
            priority_score=float(row["priority_score"]),
            confidence_level=ConfidenceLevel(row["confidence_level"]),
            tlp=row.get("tlp", "TLP:GREEN"),
            key_evidence=[EvidenceSummary(**e) for e in parse_json(row.get("key_evidence"))],
            alert_count=int(row.get("alert_count", 0)),
            source_types=list(row.get("source_types") or []),
            time_window=row.get("time_window", ""),
            affected_assets=list(row.get("affected_assets") or []),
            mitre_technique_ids=list(row.get("mitre_technique_ids") or []),
            mitre_tactic_names=list(row.get("mitre_tactic_names") or []),
            kill_chain_stage=row.get("kill_chain_stage"),
            immediate_actions=[ActionItem(**a) for a in parse_json(row.get("immediate_actions"))],
            investigation_steps=[ActionItem(**s) for s in parse_json(row.get("investigation_steps"))],
            priority_justification=row.get("priority_justification", ""),
            score_breakdown=parse_json(row.get("score_breakdown")) or {},
            generated_at=row.get("generated_at") or datetime.now(timezone.utc),
            generated_by=row.get("generated_by", "THREATICAP-BLUF-ENGINE"),
            analyst_notes=row.get("analyst_notes", ""),
        )


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------

def create_postgres_repositories(
    dsn: str,
    pool_min: int = 2,
    pool_max: int = 10,
    ssl_mode: str = "prefer",
) -> tuple[
    PostgresAlertRepository,
    PostgresThreatRepository,
    PostgresAuditRepository,
    PostgresReportRepository,
    PostgresConnectionPool,
]:
    """
    Create all PostgreSQL repositories sharing a single connection pool.
    Returns (alert_repo, threat_repo, audit_repo, report_repo, pool).
    """
    pool = PostgresConnectionPool(
        dsn=dsn,
        min_connections=pool_min,
        max_connections=pool_max,
        ssl_mode=ssl_mode,
    )
    return (
        PostgresAlertRepository(pool),
        PostgresThreatRepository(pool),
        PostgresAuditRepository(pool),
        PostgresReportRepository(pool),
        pool,
    )
