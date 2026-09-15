"""
MISP connector — ingests threat intelligence from a MISP instance.

Supports:
- Fetching events from a MISP API (with configurable filters)
- Converting MISP events → THREATICAP Alerts
- Pushing THREATICAP IoCs back to MISP as sightings

Configuration (config.yaml → integrations.misp):
    enabled: true
    url: "https://misp.example.mil"
    api_key: ""          # set via MISP_API_KEY env var
    verify_ssl: true     # set false only for air-gapped self-signed certs
    event_filters:
        tags: ["tlp:amber", "tlp:red"]
        org_id: null
        limit: 100
    push_sightings: true
    source_reliability: 0.80

Implements BaseConnector interface so it plugs directly into the ingestion
pipeline without modification.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError

from threaticap.models.alert import (
    Alert, AlertSeverity, AlertSource, AlertStatus,
    AssetContext, Observable, ObservableType,
)

logger = logging.getLogger(__name__)

# MISP attribute type → ObservableType mapping
_MISP_TYPE_MAP: dict[str, ObservableType] = {
    "ip-src":           ObservableType.IP_ADDRESS,
    "ip-dst":           ObservableType.IP_ADDRESS,
    "ip-src|port":      ObservableType.IP_ADDRESS,
    "ip-dst|port":      ObservableType.IP_ADDRESS,
    "domain":           ObservableType.DOMAIN,
    "hostname":         ObservableType.DOMAIN,
    "url":              ObservableType.URL,
    "md5":              ObservableType.FILE_HASH,
    "sha1":             ObservableType.FILE_HASH,
    "sha256":           ObservableType.FILE_HASH,
    "email-src":        ObservableType.EMAIL,
    "email-dst":        ObservableType.EMAIL,
    "vulnerability":    ObservableType.CVE,
}

_MISP_THREAT_LEVEL: dict[str, AlertSeverity] = {
    "1": AlertSeverity.CRITICAL,    # High
    "2": AlertSeverity.HIGH,        # Medium
    "3": AlertSeverity.MEDIUM,      # Low
    "4": AlertSeverity.INFO,        # Undefined
}


class MISPConnector:
    """
    Ingests threat intelligence from a MISP platform.

    In production, the connector calls the MISP REST API.  When the
    MISP instance is unreachable (e.g. air-gapped operation), it falls
    back to loading a cached MISP export JSON file.

    This is a batch-pull connector (not a streaming connector) and does not
    implement the streaming BaseConnector interface.
    """

    SOURCE_ID = "misp"

    def __init__(
        self,
        url: str,
        api_key: str | None = None,
        verify_ssl: bool = True,
        event_filters: dict[str, Any] | None = None,
        push_sightings: bool = True,
        source_reliability: float = 0.80,
        cache_path: str | None = None,
    ) -> None:
        self._url = url.rstrip("/")
        self._api_key = api_key or os.environ.get("MISP_API_KEY", "")
        self._verify_ssl = verify_ssl
        self._filters = event_filters or {}
        self._push_sightings = push_sightings
        self._source_reliability = source_reliability
        self._cache_path = cache_path
        self._session: Any = None  # requests.Session injected lazily

    # ------------------------------------------------------------------
    # BaseConnector interface
    # ------------------------------------------------------------------

    def fetch(self) -> list[dict[str, Any]]:
        """Fetch raw MISP events. Falls back to cache on connectivity failure."""
        try:
            return self._fetch_from_api()
        except Exception as exc:
            logger.warning("MISP API unreachable (%s) — trying cache fallback", exc)
            if self._cache_path:
                return self._load_cache()
            return []

    def normalise(self, raw_events: list[dict[str, Any]]) -> list[Alert]:
        """Convert MISP events to THREATICAP Alerts."""
        alerts: list[Alert] = []
        for event in raw_events:
            try:
                alert = self._event_to_alert(event)
                if alert:
                    alerts.append(alert)
            except Exception as exc:
                logger.error("MISP event normalisation failed: %s", exc)
        logger.info("MISP: normalised %d events to %d alerts", len(raw_events), len(alerts))
        return alerts

    # ------------------------------------------------------------------
    # MISP API methods
    # ------------------------------------------------------------------

    def _fetch_from_api(self) -> list[dict[str, Any]]:
        """Call MISP REST API /events/restSearch."""
        import urllib.request
        import json as _json

        search_params: dict[str, Any] = {
            "returnFormat": "json",
            "limit": self._filters.get("limit", 100),
        }
        if self._filters.get("tags"):
            search_params["tags"] = self._filters["tags"]
        if self._filters.get("org_id"):
            search_params["org"] = self._filters["org_id"]

        url = f"{self._url}/events/restSearch"
        req = urllib.request.Request(
            url,
            data=_json.dumps(search_params).encode(),
            headers={
                "Authorization": self._api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        # In production, use requests with SSL verification / mTLS
        import ssl
        ctx = ssl.create_default_context() if self._verify_ssl else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not self._verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            data = _json.loads(resp.read())

        events = data.get("response", [])
        logger.info("MISP: fetched %d events from %s", len(events), self._url)
        if self._cache_path:
            self._save_cache(events)
        return events

    def _load_cache(self) -> list[dict[str, Any]]:
        import json as _json
        try:
            with open(self._cache_path, "r", encoding="utf-8") as fh:  # type: ignore[arg-type]
                data = _json.load(fh)
            logger.info("MISP: loaded %d events from cache %s", len(data), self._cache_path)
            return data if isinstance(data, list) else []
        except Exception as exc:
            logger.error("MISP cache load failed: %s", exc)
            return []

    def _save_cache(self, events: list[dict[str, Any]]) -> None:
        import json as _json
        try:
            with open(self._cache_path, "w", encoding="utf-8") as fh:  # type: ignore[arg-type]
                _json.dump(events, fh)
        except Exception as exc:
            logger.warning("MISP cache save failed: %s", exc)

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _event_to_alert(self, event_wrapper: dict[str, Any]) -> Alert | None:
        event = event_wrapper.get("Event", event_wrapper)
        if not event:
            return None

        event_id = str(event.get("id", ""))
        event_uuid = event.get("uuid", event_id)
        title = event.get("info", f"MISP Event {event_id}")
        threat_level = str(event.get("threat_level_id", "4"))
        severity = _MISP_THREAT_LEVEL.get(threat_level, AlertSeverity.MEDIUM)

        # Parse timestamp
        ts_raw = event.get("timestamp") or event.get("date")
        try:
            ts = datetime.fromtimestamp(int(ts_raw), tz=timezone.utc) if ts_raw else datetime.now(timezone.utc)
        except (TypeError, ValueError):
            ts = datetime.now(timezone.utc)

        # Extract observables from MISP Attributes
        observables: list[Observable] = []
        for attr in event.get("Attribute", []):
            obs_type = _MISP_TYPE_MAP.get(attr.get("type", ""))
            value = attr.get("value", "")
            if obs_type and value:
                # Strip port from ip|port values
                if "|" in value:
                    value = value.split("|")[0]
                observables.append(Observable(
                    type=obs_type,
                    value=value[:2048],
                    confidence=0.8 if not attr.get("to_ids") else 0.9,
                    context=attr.get("comment", ""),
                ))

        # Galaxy / cluster → MITRE technique IDs
        mitre_ids: list[str] = []
        for galaxy in event.get("Galaxy", []):
            for cluster in galaxy.get("GalaxyCluster", []):
                tag = cluster.get("tag_name", "")
                if "mitre-attack-pattern" in tag or "T" in tag:
                    # Extract T#### pattern
                    import re
                    found = re.findall(r"T\d{4}(?:\.\d{3})?", tag)
                    mitre_ids.extend(found)

        # TLP from tags
        tlp = "TLP:AMBER"  # safe default for MISP
        for tag_obj in event.get("Tag", []):
            tag_name = tag_obj.get("name", "").upper()
            if "TLP:RED" in tag_name:
                tlp = "TLP:RED"
                break
            if "TLP:AMBER+STRICT" in tag_name:
                tlp = "TLP:AMBER+STRICT"
            elif "TLP:AMBER" in tag_name and tlp not in ("TLP:RED",):
                tlp = "TLP:AMBER"
            elif "TLP:GREEN" in tag_name and tlp not in ("TLP:RED", "TLP:AMBER"):
                tlp = "TLP:GREEN"

        return Alert(
            source_ref=event_uuid,
            source_type=AlertSource.STIX_TAXII,
            source_id=self.SOURCE_ID,
            source_reliability=self._source_reliability,
            event_time=ts,
            severity=severity,
            confidence=float(event.get("analysis", 0)) / 2.0,  # MISP: 0=initial,1=ongoing,2=complete
            title=title[:512],
            description=f"MISP Event {event_id}: {title}",
            observables=observables,
            mitre_technique_ids=list(set(mitre_ids)),
            asset_context=AssetContext(),
            tlp=tlp,
            status=AlertStatus.INGESTED,
        )

    def push_sighting(self, observable_value: str, source: str = "THREATICAP") -> bool:
        """
        Push a sighting back to MISP for the given observable value.
        Returns True on success, False on failure (gracefully degrades).
        """
        if not self._push_sightings or not self._api_key:
            return False
        try:
            import urllib.request, json as _json
            payload = _json.dumps({
                "value": observable_value,
                "source": source,
                "type": "0",  # Sighting
            }).encode()
            req = urllib.request.Request(
                f"{self._url}/sightings/add",
                data=payload,
                headers={
                    "Authorization": self._api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            import ssl
            ctx = ssl.create_default_context() if self._verify_ssl else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if not self._verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            urllib.request.urlopen(req, context=ctx, timeout=10)
            return True
        except Exception as exc:
            logger.warning("MISP sighting push failed: %s", exc)
            return False
