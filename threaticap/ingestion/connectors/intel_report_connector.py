"""
Intelligence Report connector — handles structured and free-text intel reports.

Sources:
- HUMINT / SIGINT reports (JSON with free-text body)
- Satellite / ISR reports (structured JSON)
- OSINT digests
- Internal analytical products

Key capability: extracts structured observables from free-text using pattern
matching, with confidence scoring that reflects extraction vs. authoritative data.
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from threaticap.ingestion.base_connector import BaseConnector, ConnectorConfig, ConnectorError
from threaticap.ingestion.normaliser import AlertNormaliser, IOC_PATTERNS
from threaticap.models.alert import Alert, AlertSource, AssetContext, Observable, ObservableType

logger = logging.getLogger(__name__)

# Source subtype → AlertSource mapping
SOURCE_SUBTYPE_MAP: dict[str, AlertSource] = {
    "humint":        AlertSource.HUMINT,
    "sigint":        AlertSource.SIGINT,
    "osint":         AlertSource.OSINT,
    "satellite":     AlertSource.SATELLITE_ISR,
    "isr":           AlertSource.SATELLITE_ISR,
    "commercial":    AlertSource.COMMERCIAL_FEED,
}


class IntelReportConnector(BaseConnector):
    """
    Intelligence report connector with free-text IOC extraction.

    Configuration (ConnectorConfig.extra keys):
        file_path:      path to JSON report file (batch mode)
        source_subtype: "humint" | "sigint" | "osint" | "satellite" | "isr"
        default_tlp:    TLP classification (default: "TLP:AMBER")
    """

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)
        self._file_path: Path | None = None
        self._source_subtype = config.extra.get("source_subtype", "osint").lower()
        self._default_tlp = config.extra.get("default_tlp", "TLP:AMBER")

        path_str = config.extra.get("file_path", "")
        if path_str:
            self._file_path = Path(path_str)

        self._source_type = SOURCE_SUBTYPE_MAP.get(self._source_subtype, AlertSource.OSINT)

    def connect(self) -> None:
        if self._file_path and not self._file_path.exists():
            raise ConnectorError(
                f"Intel report file not found: {self._file_path}",
                self.connector_id,
            )
        self._connected = True
        self._log.info(
            "Intel report connector connected (%s): %s",
            self._source_subtype, self._file_path
        )

    def disconnect(self) -> None:
        self._connected = False

    def fetch_raw(self) -> Iterator[dict[str, Any]]:
        if not self._file_path:
            return
        with open(self._file_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        records = data if isinstance(data, list) else data.get("reports", [data])
        yield from records

    def normalise(self, raw: dict[str, Any]) -> Alert | None:
        """
        Normalise an intelligence report to canonical Alert.

        The 'body' / 'text' field is processed for IOC extraction.
        Confidence is lower for extracted IOCs than for structured fields.
        """
        # Collect free text for IOC extraction
        free_text_fields = ["body", "text", "content", "description", "summary", "narrative"]
        free_text = " ".join(
            str(raw[f]) for f in free_text_fields if f in raw and raw[f]
        )

        # Structured observables (high confidence)
        observables: list[Observable] = []
        for key, obs_type in [
            ("ip_addresses",    ObservableType.IP_ADDRESS),
            ("domains",         ObservableType.DOMAIN),
            ("file_hashes",     ObservableType.FILE_HASH),
            ("urls",            ObservableType.URL),
            ("email_addresses", ObservableType.EMAIL),
            ("cves",            ObservableType.CVE),
        ]:
            values = raw.get(key, [])
            if isinstance(values, str):
                values = [values]
            for val in values:
                if val:
                    observables.append(Observable(
                        type=obs_type,
                        value=str(val),
                        confidence=0.9,
                        context="Structured intel report field",
                    ))

        # Extract from free text (lower confidence)
        if free_text:
            existing_values = {o.value.lower() for o in observables}
            for obs_type, pattern in IOC_PATTERNS:
                for match in pattern.finditer(free_text):
                    val = match.group(0)
                    if val.lower() not in existing_values:
                        observables.append(Observable(
                            type=obs_type,
                            value=val,
                            confidence=0.5,
                            context="Extracted from intel report text",
                        ))
                        existing_values.add(val.lower())

        severity = AlertNormaliser.normalise_severity(
            str(raw.get("severity", raw.get("threat_level", "medium")))
        )

        event_time_raw = raw.get("report_date") or raw.get("date") or raw.get("timestamp")
        event_time = self._parse_time(event_time_raw)

        # Build a meaningful title
        title = (
            raw.get("title") or raw.get("subject") or
            raw.get("report_title") or f"Intel Report {raw.get('report_id', '')}"
        ).strip() or "Intelligence Report"

        # MITRE from report
        mitre_ids: list[str] = []
        for key in ("mitre_technique_ids", "mitre_techniques", "techniques"):
            val = raw.get(key, [])
            if isinstance(val, list):
                mitre_ids.extend(str(t).strip() for t in val if t)
                break
            elif isinstance(val, str):
                mitre_ids = [t.strip() for t in val.split(",") if t.strip()]
                break

        asset = AssetContext(
            network_segment=raw.get("target_network"),
            tags=raw.get("tags", []),
        )

        try:
            return Alert(
                source_ref=str(raw.get("report_id") or raw.get("id") or str(uuid.uuid4())),
                source_type=self._source_type,
                source_id=self.connector_id,
                source_reliability=self.source_reliability,
                event_time=event_time,
                severity=severity,
                confidence=float(raw.get("confidence", 0.6)),
                title=title,
                description=free_text[:8192] if free_text else str(raw.get("description", "")),
                category=str(raw.get("category") or raw.get("report_type", "Intelligence")),
                rule_id=raw.get("report_id"),
                raw_payload=raw,
                observables=observables,
                asset_context=asset,
                mitre_technique_ids=mitre_ids,
                threat_actor=raw.get("threat_actor") or raw.get("actor"),
                campaign=raw.get("campaign"),
                tlp=raw.get("tlp", self._default_tlp),
            )
        except Exception as exc:
            self._log.error("Intel report normalisation failed: %s", exc)
            raise

    @staticmethod
    def _parse_time(raw: Any) -> datetime:
        if raw is None:
            return datetime.now(timezone.utc)
        if isinstance(raw, str):
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now(timezone.utc)
