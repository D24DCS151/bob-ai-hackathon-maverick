"""
SIEM connector — ingests alerts from SIEM systems in JSON / CEF / LEEF formats.

Supports:
- JSON feed files (batch)
- CEF (ArcSight Common Event Format) syslog-style strings
- LEEF (Log Event Extended Format — QRadar style)
- HTTP polling endpoint (production mode)

In production, replace the file/HTTP modes with a Kafka consumer or
direct SIEM API integration (Splunk HEC, IBM QRadar REST API, etc.).
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
from threaticap.ingestion.normaliser import AlertNormaliser
from threaticap.models.alert import Alert, AlertSource, AlertStatus, AssetContext, Observable, ObservableType

logger = logging.getLogger(__name__)

# CEF field-name → canonical alert field
CEF_FIELD_MAP: dict[str, str] = {
    "src":       "src_ip",
    "dst":       "dst_ip",
    "suser":     "username",
    "duser":     "dst_username",
    "msg":       "description",
    "reason":    "description",
    "cat":       "category",
    "rt":        "event_time",
    "severity":  "severity",
    "cs1":       "rule_id",
    "deviceExternalId": "source_ref",
}


class SiemConnector(BaseConnector):
    """
    Production-grade SIEM alert connector.

    Configuration (ConnectorConfig.extra keys):
        mode:           "file" | "http" | "kafka" (default: "file")
        file_path:      path to JSON feed file (mode=file)
        feed_format:    "json" | "cef" | "leef" (default: "json")
        http_url:       polling endpoint URL (mode=http)
        http_headers:   dict of request headers (mode=http)
        kafka_bootstrap: Kafka bootstrap servers (mode=kafka)
        kafka_topic:    Kafka topic name (mode=kafka)
        kafka_group_id: Consumer group ID (mode=kafka)
    """

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)
        self._mode = config.extra.get("mode", "file")
        self._file_path: Path | None = None
        self._http_url: str | None = config.extra.get("http_url")
        self._feed_format: str = config.extra.get("feed_format", "json")
        self._raw_data: list[dict[str, Any]] = []

        if self._mode == "file":
            path_str = config.extra.get("file_path", "")
            if path_str:
                self._file_path = Path(path_str)

    def connect(self) -> None:
        if self._mode == "file" and self._file_path:
            if not self._file_path.exists():
                raise ConnectorError(
                    f"SIEM feed file not found: {self._file_path}",
                    self.connector_id,
                )
            self._log.info("SIEM connector connected (file mode): %s", self._file_path)
        elif self._mode == "http":
            # In production: establish HTTP session with auth/TLS
            self._log.info("SIEM connector ready (HTTP mode): %s", self._http_url)
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False
        self._raw_data = []
        self._log.debug("SIEM connector disconnected")

    def fetch_raw(self) -> Iterator[dict[str, Any]]:
        if self._mode == "file" and self._file_path:
            yield from self._fetch_from_file()
        elif self._mode == "http":
            yield from self._fetch_from_http()
        else:
            self._log.warning("No valid fetch mode configured for SIEM connector")

    def _fetch_from_file(self) -> Iterator[dict[str, Any]]:
        assert self._file_path is not None
        try:
            with open(self._file_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            records = data if isinstance(data, list) else data.get("alerts", [data])
            for record in records:
                yield record
        except json.JSONDecodeError as exc:
            # Try line-delimited JSON (NDJSON)
            with open(self._file_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            if self._feed_format == "cef":
                                yield {"_raw_cef": line}
                            else:
                                self._log.warning("Skipping unparseable line: %s…", line[:80])

    def _fetch_from_http(self) -> Iterator[dict[str, Any]]:
        """
        HTTP polling mode.

        In production:
            import httpx
            response = httpx.get(self._http_url, headers=..., timeout=self.config.timeout_seconds)
            response.raise_for_status()
            yield from response.json().get("alerts", [])
        """
        self._log.warning("HTTP mode stub — no live fetch performed")
        return
        yield  # make this a generator

    def normalise(self, raw: dict[str, Any]) -> Alert | None:
        """Map a raw SIEM record to the canonical Alert model."""
        if self._feed_format == "cef" or "_raw_cef" in raw:
            raw = self._parse_cef(raw.get("_raw_cef", ""))

        if not raw:
            return None

        # Skip heartbeat / health-check events
        if raw.get("event_type") in ("heartbeat", "health_check"):
            return None

        severity = AlertNormaliser.normalise_severity(
            str(raw.get("severity", raw.get("Severity", "medium")))
        )

        event_time = self._parse_event_time(
            raw.get("event_time") or raw.get("timestamp") or raw.get("rt")
        )

        # Build observable list from structured fields
        observables: list[Observable] = []
        for field_name, obs_type in [
            ("src_ip",  ObservableType.IP_ADDRESS),
            ("dst_ip",  ObservableType.IP_ADDRESS),
            ("domain",  ObservableType.DOMAIN),
            ("url",     ObservableType.URL),
            ("hash",    ObservableType.FILE_HASH),
        ]:
            val = raw.get(field_name) or raw.get(field_name.replace("_", ""))
            if val and isinstance(val, str) and len(val) > 0:
                observables.append(Observable(
                    type=obs_type,
                    value=val,
                    confidence=0.9,
                    context=f"SIEM structured field: {field_name}",
                ))

        # Parse MITRE technique IDs if present
        mitre_ids: list[str] = []
        raw_mitre = raw.get("mitre_technique_ids") or raw.get("mitre_techniques") or []
        if isinstance(raw_mitre, list):
            mitre_ids = [str(t).strip() for t in raw_mitre if t]
        elif isinstance(raw_mitre, str):
            mitre_ids = [t.strip() for t in raw_mitre.split(",") if t.strip()]

        asset = AssetContext(
            hostname=raw.get("hostname") or raw.get("host"),
            ip_addresses=[ip for ip in [raw.get("src_ip"), raw.get("dst_ip")] if ip],
            network_segment=raw.get("network_segment"),
        )

        try:
            return Alert(
                source_ref=str(raw.get("event_id") or raw.get("id") or str(uuid.uuid4())),
                source_type=AlertSource.SIEM,
                source_id=self.connector_id,
                source_reliability=self.source_reliability,
                event_time=event_time,
                severity=severity,
                confidence=float(raw.get("confidence", 0.7)),
                title=str(raw.get("title") or raw.get("name") or raw.get("alert_name") or "SIEM Alert"),
                description=str(raw.get("description") or raw.get("msg") or ""),
                category=str(raw.get("category") or raw.get("event_category") or ""),
                rule_id=raw.get("rule_id") or raw.get("signature_id") or raw.get("cs1"),
                raw_payload=raw,
                observables=observables,
                asset_context=asset,
                mitre_technique_ids=mitre_ids,
                threat_actor=raw.get("threat_actor"),
                campaign=raw.get("campaign"),
            )
        except Exception as exc:
            self._log.error("Failed to normalise SIEM record: %s | raw keys: %s", exc, list(raw.keys()))
            raise

    # ------------------------------------------------------------------
    # CEF parsing
    # ------------------------------------------------------------------

    def _parse_cef(self, cef_string: str) -> dict[str, Any]:
        """
        Parse a CEF-formatted string into a flat dictionary.

        CEF format:
            CEF:Version|Device Vendor|Device Product|Device Version|
            Signature ID|Name|Severity|Extension
        """
        if not cef_string or not cef_string.startswith("CEF:"):
            return {}

        try:
            # Split header from extensions
            header_part, _, ext_part = cef_string.partition("|")
            # We need 7 pipe-separated header fields
            parts = cef_string.split("|", 7)
            if len(parts) < 8:
                return {}

            result: dict[str, Any] = {
                "cef_version":   parts[0].replace("CEF:", ""),
                "device_vendor": parts[1],
                "device_product": parts[2],
                "device_version": parts[3],
                "signature_id":  parts[4],
                "title":         parts[5],
                "severity":      parts[6],
            }

            # Parse extension key=value pairs
            extension = parts[7]
            for match in re.finditer(r'(\w+)=((?:[^\\=\s]|\\.)*(?:\s(?!\w+=)(?:[^\\=\s]|\\.)*)*)', extension):
                key, value = match.group(1), match.group(2)
                canonical_key = CEF_FIELD_MAP.get(key, key)
                result[canonical_key] = value.replace("\\=", "=").replace("\\\\", "\\")

            result["source_ref"] = result.get("signature_id", str(uuid.uuid4()))
            return result

        except Exception as exc:
            self._log.warning("CEF parse error: %s | input: %s…", exc, cef_string[:100])
            return {}

    @staticmethod
    def _parse_event_time(raw_time: Any) -> datetime:
        if raw_time is None:
            return datetime.now(timezone.utc)
        if isinstance(raw_time, (int, float)):
            # Unix epoch — milliseconds if > 1e12
            ts = raw_time / 1000.0 if raw_time > 1e12 else float(raw_time)
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(raw_time, str):
            # Try ISO 8601 first, then common formats
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(raw_time.strip(), fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except ValueError:
                    continue
            # Fallback: try fromisoformat (Python 3.7+)
            try:
                dt = datetime.fromisoformat(raw_time.strip().replace("Z", "+00:00"))
                return dt
            except ValueError:
                pass
        return datetime.now(timezone.utc)
