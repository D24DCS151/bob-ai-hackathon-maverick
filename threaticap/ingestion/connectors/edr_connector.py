"""
EDR / Network Sensor connector — ingests endpoint detection and telemetry data.

Supports:
- JSON structured endpoint telemetry
- CSV network flow records
- Syslog-style process execution logs

In production, connect to CrowdStrike Falcon, Microsoft Defender for Endpoint,
Carbon Black, Darktrace, or similar via their respective APIs.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from threaticap.ingestion.base_connector import BaseConnector, ConnectorConfig, ConnectorError
from threaticap.ingestion.normaliser import AlertNormaliser
from threaticap.models.alert import Alert, AlertSource, AssetContext, Observable, ObservableType

logger = logging.getLogger(__name__)


class EdrConnector(BaseConnector):
    """
    EDR / network sensor connector.

    Configuration (ConnectorConfig.extra keys):
        mode:           "file" | "api" (default: "file")
        file_path:      path to telemetry file
        feed_format:    "json" | "csv" | "syslog" (default: "json")
        source_subtype: "edr" | "network" | "endpoint" (used for source_type)
    """

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)
        self._mode = config.extra.get("mode", "file")
        self._feed_format = config.extra.get("feed_format", "json")
        self._source_subtype = config.extra.get("source_subtype", "edr")
        self._file_path: Path | None = None

        if self._mode == "file":
            path_str = config.extra.get("file_path", "")
            if path_str:
                self._file_path = Path(path_str)

    def connect(self) -> None:
        if self._mode == "file" and self._file_path:
            if not self._file_path.exists():
                raise ConnectorError(
                    f"EDR feed file not found: {self._file_path}",
                    self.connector_id,
                )
        self._connected = True
        self._log.info("EDR connector connected (%s mode)", self._mode)

    def disconnect(self) -> None:
        self._connected = False

    def fetch_raw(self) -> Iterator[dict[str, Any]]:
        if not self._file_path:
            return

        if self._feed_format == "json":
            yield from self._fetch_json()
        elif self._feed_format == "csv":
            yield from self._fetch_csv()
        elif self._feed_format == "syslog":
            yield from self._fetch_syslog()

    def _fetch_json(self) -> Iterator[dict[str, Any]]:
        assert self._file_path is not None
        with open(self._file_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        records = data if isinstance(data, list) else data.get("events", [data])
        yield from records

    def _fetch_csv(self) -> Iterator[dict[str, Any]]:
        """Parse CSV network flow records."""
        assert self._file_path is not None
        with open(self._file_path, "r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                yield dict(row)

    def _fetch_syslog(self) -> Iterator[dict[str, Any]]:
        """Parse simple syslog-style lines into structured dicts."""
        assert self._file_path is not None
        import re
        # Basic syslog pattern: timestamp host process[pid]: message
        pattern = re.compile(
            r"^(?P<ts>\S+\s+\S+\s+\S+)\s+(?P<host>\S+)\s+(?P<proc>[^\[]+)"
            r"(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<msg>.+)$"
        )
        with open(self._file_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    yield {
                        "timestamp": m.group("ts"),
                        "hostname": m.group("host"),
                        "process": m.group("proc").strip(),
                        "pid": m.group("pid"),
                        "message": m.group("msg"),
                        "_raw": line,
                    }
                else:
                    yield {"message": line, "_raw": line}

    def normalise(self, raw: dict[str, Any]) -> Alert | None:
        """Normalise EDR/sensor telemetry to canonical Alert."""
        # Determine source type from subtype
        source_type_map = {
            "edr":      AlertSource.EDR,
            "network":  AlertSource.NETWORK_SENSOR,
            "endpoint": AlertSource.EDR,
        }
        source_type = source_type_map.get(self._source_subtype, AlertSource.EDR)

        # Build observables
        observables: list[Observable] = []
        for field_name, obs_type in [
            ("src_ip",        ObservableType.IP_ADDRESS),
            ("dst_ip",        ObservableType.IP_ADDRESS),
            ("source_ip",     ObservableType.IP_ADDRESS),
            ("dest_ip",       ObservableType.IP_ADDRESS),
            ("remote_ip",     ObservableType.IP_ADDRESS),
            ("domain",        ObservableType.DOMAIN),
            ("file_hash",     ObservableType.FILE_HASH),
            ("sha256",        ObservableType.FILE_HASH),
            ("md5",           ObservableType.FILE_HASH),
            ("parent_process",ObservableType.PROCESS),
            ("process_name",  ObservableType.PROCESS),
        ]:
            val = raw.get(field_name)
            if val and isinstance(val, str):
                observables.append(Observable(
                    type=obs_type,
                    value=val,
                    confidence=0.9,
                    context=f"EDR field: {field_name}",
                ))

        severity = AlertNormaliser.normalise_severity(
            str(raw.get("severity", raw.get("risk_score", "medium")))
        )

        event_time_raw = (
            raw.get("timestamp") or raw.get("event_time") or raw.get("created_at")
        )
        event_time = self._parse_time(event_time_raw)

        # Build description from available fields
        description_parts = []
        if raw.get("process_name"):
            description_parts.append(f"Process: {raw['process_name']}")
        if raw.get("command_line"):
            description_parts.append(f"Command: {raw['command_line']}")
        if raw.get("file_path"):
            description_parts.append(f"File: {raw['file_path']}")
        if raw.get("message"):
            description_parts.append(raw["message"])
        description = " | ".join(description_parts) or str(raw.get("description", ""))

        # MITRE mapping from EDR telemetry
        mitre_ids: list[str] = []
        raw_mitre = raw.get("mitre_technique_ids") or raw.get("techniques") or []
        if isinstance(raw_mitre, list):
            mitre_ids = [str(t).strip() for t in raw_mitre if t]
        elif isinstance(raw_mitre, str):
            mitre_ids = [t.strip() for t in raw_mitre.split(",") if t.strip()]

        asset = AssetContext(
            hostname=raw.get("hostname") or raw.get("host") or raw.get("device_name"),
            ip_addresses=[
                ip for ip in [
                    raw.get("src_ip"), raw.get("source_ip"),
                    raw.get("dst_ip"), raw.get("dest_ip"),
                ] if ip
            ],
            asset_id=raw.get("device_id") or raw.get("asset_id"),
        )

        try:
            return Alert(
                source_ref=str(
                    raw.get("event_id") or raw.get("id") or raw.get("detection_id") or str(uuid.uuid4())
                ),
                source_type=source_type,
                source_id=self.connector_id,
                source_reliability=self.source_reliability,
                event_time=event_time,
                severity=severity,
                confidence=float(raw.get("confidence", raw.get("score", 0.75))),
                title=str(
                    raw.get("title") or raw.get("alert_name") or
                    raw.get("detection_name") or raw.get("event_type", "EDR Event")
                ),
                description=description,
                category=str(raw.get("category") or raw.get("event_type", "")),
                rule_id=raw.get("rule_id") or raw.get("detection_id") or raw.get("signature"),
                raw_payload=raw,
                observables=observables,
                asset_context=asset,
                mitre_technique_ids=mitre_ids,
                threat_actor=raw.get("threat_actor"),
                campaign=raw.get("campaign"),
            )
        except Exception as exc:
            self._log.error("EDR normalisation failed: %s", exc)
            raise

    @staticmethod
    def _parse_time(raw: Any) -> datetime:
        if raw is None:
            return datetime.now(timezone.utc)
        if isinstance(raw, (int, float)):
            ts = raw / 1000.0 if raw > 1e12 else float(raw)
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(raw, str):
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now(timezone.utc)
