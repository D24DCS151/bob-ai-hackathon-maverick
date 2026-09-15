"""
Satellite / ISR (Intelligence, Surveillance, Reconnaissance) feed connector.

Handles structured intelligence products from satellite and ISR platforms.

Source types supported:
- Overhead imagery analysis reports (JSON structured)
- Signals intelligence (SIGINT) summary feeds
- Electronic intelligence (ELINT) activity logs
- Space-based surveillance alerts

Classification handling:
- All ISR data is automatically assigned TLP:RED
- Source reliability defaults reflect national-source weighting
- Free-text field extraction uses the same IOC patterns as intel_report_connector

Real-world integration points:
- National imagery exploitation systems (NSG/OSINT)
- Tactical data links (Link 16, VMF)
- Intelligence community shared services
- Commercial satellite imagery providers (Maxar, Planet)

This connector is intentionally simplified — real classified system
integration requires ISSO-approved interfaces and proper access controls
at the network layer.
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
from threaticap.models.alert import Alert, AlertSource, AssetContext, GeoLocation, Observable, ObservableType

logger = logging.getLogger(__name__)


class SatelliteISRConnector(BaseConnector):
    """
    Satellite / ISR feed connector.

    Configuration (ConnectorConfig.extra keys):
        file_path:          path to JSON feed file
        source_subtype:     "satellite" | "sigint" | "elint" | "imagery"
        default_tlp:        TLP classification (always TLP:RED for classified)
        mission_area:       Geographic mission area identifier
    """

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)
        self._file_path: Path | None = None
        self._source_subtype = config.extra.get("source_subtype", "satellite").lower()
        self._default_tlp = config.extra.get("default_tlp", "TLP:RED")
        self._mission_area = config.extra.get("mission_area", "")

        path_str = config.extra.get("file_path", "")
        if path_str:
            self._file_path = Path(path_str)

    def connect(self) -> None:
        if self._file_path and not self._file_path.exists():
            raise ConnectorError(
                f"ISR feed file not found: {self._file_path}",
                self.connector_id,
            )
        self._connected = True
        self._log.info(
            "Satellite/ISR connector connected (%s mode)", self._source_subtype
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
        Normalise a satellite/ISR report to canonical Alert.

        ISR reports typically contain:
        - Geolocation data (lat/lon of observed activity)
        - Entity/activity classification
        - Temporal coverage window
        - Associated threat indicators
        - Confidence assessment
        """
        # Skip non-relevant entries
        if raw.get("report_type", "").lower() in ("routine", "admin", "logistic"):
            return None

        # Collect free text for IOC extraction
        free_text_fields = [
            "summary", "narrative", "analysis", "description",
            "activity_description", "target_description"
        ]
        free_text = " ".join(
            str(raw[f]) for f in free_text_fields if f in raw and raw[f]
        )

        # Build observables from structured fields
        observables: list[Observable] = []

        # Geolocation as custom observable
        lat = raw.get("latitude") or raw.get("lat")
        lon = raw.get("longitude") or raw.get("lon")
        if lat and lon:
            try:
                observables.append(Observable(
                    type=ObservableType.CUSTOM,
                    value=f"GEO:{float(lat):.4f},{float(lon):.4f}",
                    confidence=0.95,
                    context="Satellite-observed geolocation",
                ))
            except (ValueError, TypeError):
                pass

        # Target identifiers
        for field_name, obs_type in [
            ("target_ip", ObservableType.IP_ADDRESS),
            ("target_domain", ObservableType.DOMAIN),
            ("vessel_mmsi", ObservableType.CUSTOM),  # Maritime vessel ID
            ("aircraft_icao", ObservableType.CUSTOM),  # Aircraft ICAO code
            ("vehicle_id", ObservableType.CUSTOM),
        ]:
            val = raw.get(field_name)
            if val:
                type_val = obs_type
                if field_name in ("vessel_mmsi", "aircraft_icao", "vehicle_id"):
                    val = f"{field_name.upper()}:{val}"
                observables.append(Observable(
                    type=type_val,
                    value=str(val),
                    confidence=0.9,
                    context=f"ISR structured field: {field_name}",
                ))

        # Extract IOCs from free text
        if free_text:
            existing_values = {o.value.lower() for o in observables}
            for obs_type, pattern in IOC_PATTERNS:
                for match in pattern.finditer(free_text):
                    val = match.group(0)
                    if val.lower() not in existing_values:
                        observables.append(Observable(
                            type=obs_type,
                            value=val,
                            confidence=0.55,
                            context="Extracted from ISR report text",
                        ))
                        existing_values.add(val.lower())

        # Build geolocation
        geo: GeoLocation | None = None
        if lat and lon:
            try:
                geo = GeoLocation(
                    latitude=float(lat),
                    longitude=float(lon),
                    country_code=raw.get("country_code"),
                    country_name=raw.get("country_name"),
                )
            except (ValueError, TypeError):
                pass

        severity = AlertNormaliser.normalise_severity(
            str(raw.get("severity", raw.get("threat_level", raw.get("assessment", "medium"))))
        )

        event_time_raw = (
            raw.get("observation_time") or raw.get("event_time") or
            raw.get("report_time") or raw.get("report_date") or
            raw.get("timestamp")
        )
        event_time = self._parse_time(event_time_raw)

        title = (
            raw.get("title") or raw.get("subject") or
            raw.get("event_type") or
            f"ISR Report {raw.get('report_id', uuid.uuid4().hex[:8])}"
        ).strip()

        # MITRE mapping from ISR report — try each key; skip empty lists
        mitre_ids: list[str] = []
        for key in ("mitre_technique_ids", "mitre_techniques", "techniques"):
            val = raw.get(key)
            if val is None:
                continue
            if isinstance(val, list) and val:
                mitre_ids = [str(t).strip() for t in val if t]
                break
            elif isinstance(val, str) and val.strip():
                mitre_ids = [t.strip() for t in val.split(",") if t.strip()]
                break

        asset = AssetContext(
            network_segment=raw.get("target_network") or self._mission_area,
            tags=raw.get("tags", []) + ["isr", self._source_subtype],
        )

        try:
            return Alert(
                source_ref=str(raw.get("report_id") or raw.get("id") or str(uuid.uuid4())),
                source_type=AlertSource.SATELLITE_ISR,
                source_id=self.connector_id,
                source_reliability=self.source_reliability,
                event_time=event_time,
                severity=severity,
                confidence=float(raw.get("confidence", raw.get("assessment_confidence", 0.65))),
                title=title,
                description=free_text[:8192] if free_text else str(raw.get("description", "")),
                category=str(raw.get("report_type") or raw.get("activity_type") or "ISR"),
                rule_id=raw.get("report_id"),
                raw_payload=raw,
                observables=observables,
                asset_context=asset,
                geo=geo,
                mitre_technique_ids=mitre_ids,
                threat_actor=raw.get("threat_actor") or raw.get("actor"),
                campaign=raw.get("campaign"),
                tlp=raw.get("tlp", self._default_tlp),
            )
        except Exception as exc:
            self._log.error("ISR normalisation failed: %s", exc)
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
