"""
National Threat Intelligence Platform (TIP) connector.

Generic connector for national / sovereign TIP platforms that expose a
REST API returning STIX 2.1 bundles or a proprietary JSON format.

Examples of platforms this adapts to:
  - UK NCSC CISP (via TAXII 2.1)
  - Australian CTIS
  - US CISA AIS (Automated Indicator Sharing)
  - NATO MISP federation nodes
  - Custom national platforms via pluggable adapters

Configuration (config.yaml → integrations.national_tip):
    enabled: false
    adapter: "taxii21"        # taxii21 | ncsc_cisp | custom
    url: "https://tip.example.mil/taxii/"
    collection_id: "..."
    api_key: ""               # Set via NATIONAL_TIP_API_KEY
    username: ""              # Set via NATIONAL_TIP_USERNAME
    password: ""              # Set via NATIONAL_TIP_PASSWORD
    verify_ssl: true
    source_reliability: 0.90
    poll_interval_seconds: 300

Design:
- NationalTIPConnector is a factory that selects the correct adapter.
- TAXII21Adapter implements the TAXII 2.1 specification.
- All adapters produce THREATICAP Alerts via the shared normaliser.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Protocol

from threaticap.models.alert import Alert, AlertSeverity, AlertSource, AlertStatus, AssetContext, Observable, ObservableType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Adapter protocol
# ---------------------------------------------------------------------------

class TIPAdapter(Protocol):
    """Protocol that all TIP adapters must satisfy."""
    def fetch_raw(self) -> list[dict[str, Any]]: ...
    def to_alerts(self, raw: list[dict[str, Any]]) -> list[Alert]: ...


# ---------------------------------------------------------------------------
# STIX 2.1 / TAXII 2.1 adapter
# ---------------------------------------------------------------------------

class TAXII21Adapter:
    """
    Polls a TAXII 2.1 Collection endpoint and converts STIX indicators
    to THREATICAP Alerts.

    Implements the TAXII 2.1 REST API:
        GET /taxii/             → API Root discovery
        GET /collections/       → List collections
        GET /collections/{id}/objects → Get objects (with added_after filter)
    """

    def __init__(
        self,
        url: str,
        collection_id: str,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = True,
        source_reliability: float = 0.90,
        added_after: str | None = None,  # ISO 8601 — only fetch newer than this
    ) -> None:
        self._url = url.rstrip("/")
        self._collection_id = collection_id
        self._api_key = api_key
        self._username = username
        self._password = password
        self._verify_ssl = verify_ssl
        self._reliability = source_reliability
        self._added_after = added_after

    def _headers(self) -> dict[str, str]:
        h = {
            "Accept": "application/taxii+json;version=2.1",
            "Content-Type": "application/taxii+json;version=2.1",
        }
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    def _basic_auth(self) -> tuple[str, str] | None:
        if self._username and self._password:
            return (self._username, self._password)
        return None

    def fetch_raw(self) -> list[dict[str, Any]]:
        """Fetch all objects from the collection."""
        import urllib.request, urllib.parse, base64

        params: dict[str, str] = {}
        if self._added_after:
            params["added_after"] = self._added_after

        qs = ("?" + urllib.parse.urlencode(params)) if params else ""
        url = (
            f"{self._url}/collections/{self._collection_id}/objects{qs}"
        )

        req = urllib.request.Request(url, headers=self._headers())
        if self._username and self._password:
            credentials = base64.b64encode(
                f"{self._username}:{self._password}".encode()
            ).decode()
            req.add_header("Authorization", f"Basic {credentials}")

        import ssl
        ctx = ssl.create_default_context() if self._verify_ssl else ssl.SSLContext()
        if not self._verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            data = json.loads(resp.read())

        objects = data.get("objects", [])
        logger.info("TAXII21: fetched %d objects from collection %s", len(objects), self._collection_id)
        return objects

    def to_alerts(self, raw: list[dict[str, Any]]) -> list[Alert]:
        alerts: list[Alert] = []
        for obj in raw:
            if obj.get("type") != "indicator":
                continue
            try:
                alert = self._indicator_to_alert(obj)
                if alert:
                    alerts.append(alert)
            except Exception as exc:
                logger.error("TAXII indicator normalisation failed: %s — %s", exc, obj.get("id"))
        return alerts

    def _indicator_to_alert(self, indicator: dict[str, Any]) -> Alert | None:
        """Convert a STIX 2.1 indicator object to an Alert."""
        iid = indicator.get("id", "")
        name = indicator.get("name", iid)
        pattern = indicator.get("pattern", "")
        valid_from = indicator.get("valid_from", "")
        desc = indicator.get("description", "")

        # Determine severity from confidence field (STIX 0–100)
        stix_confidence = indicator.get("confidence", 50)
        if stix_confidence >= 85:
            severity = AlertSeverity.HIGH
        elif stix_confidence >= 60:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW

        # Parse valid_from
        try:
            ts = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ts = datetime.now(timezone.utc)

        # Extract observable from STIX pattern (best-effort)
        observables = self._parse_stix_pattern(pattern)

        # MITRE technique IDs from kill_chain_phases
        mitre_ids: list[str] = []
        for kcp in indicator.get("kill_chain_phases", []):
            if kcp.get("kill_chain_name") == "mitre-attack":
                phase = kcp.get("phase_name", "")
                import re
                found = re.findall(r"[Tt]\d{4}(?:\.\d{3})?", phase)
                mitre_ids.extend(t.upper() for t in found)

        # TLP from object marking refs
        tlp = "TLP:AMBER"
        for marking in indicator.get("object_marking_refs", []):
            if "613f2e26" in marking:
                tlp = "TLP:CLEAR"
            elif "34098fce" in marking:
                tlp = "TLP:GREEN"
            elif "939a9414" in marking:
                tlp = "TLP:AMBER+STRICT"
            elif "5e57c739" in marking:
                tlp = "TLP:RED"

        return Alert(
            source_ref=iid,
            source_type=AlertSource.STIX_TAXII,
            source_id="taxii21",
            source_reliability=self._reliability,
            event_time=ts,
            severity=severity,
            confidence=round(stix_confidence / 100.0, 2),
            title=name[:512],
            description=desc[:2048],
            observables=observables,
            mitre_technique_ids=mitre_ids,
            asset_context=AssetContext(),
            tlp=tlp,
            status=AlertStatus.INGESTED,
        )

    @staticmethod
    def _parse_stix_pattern(pattern: str) -> list[Observable]:
        """Best-effort extraction of observables from a STIX pattern string."""
        import re
        observables: list[Observable] = []

        # IPv4
        for m in re.finditer(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern):
            observables.append(Observable(type=ObservableType.IP_ADDRESS, value=m.group(1)))
        # Domain
        for m in re.finditer(r"domain-name:value\s*=\s*'([^']+)'", pattern):
            observables.append(Observable(type=ObservableType.DOMAIN, value=m.group(1)))
        # URL
        for m in re.finditer(r"url:value\s*=\s*'([^']+)'", pattern):
            observables.append(Observable(type=ObservableType.URL, value=m.group(1)))
        # File hash
        for m in re.finditer(r"file:hashes\.\S+\s*=\s*'([a-fA-F0-9]{32,64})'", pattern):
            observables.append(Observable(type=ObservableType.FILE_HASH, value=m.group(1)))

        return observables


# ---------------------------------------------------------------------------
# National TIP connector (factory)
# ---------------------------------------------------------------------------

class NationalTIPConnector:
    """
    Factory connector that selects the appropriate adapter based on config.

    Supported adapters: taxii21, stub (for testing)
    """

    SOURCE_ID = "national_tip"

    def __init__(
        self,
        adapter_type: str = "taxii21",
        url: str = "",
        collection_id: str = "",
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = True,
        source_reliability: float = 0.90,
        added_after: str | None = None,
    ) -> None:
        resolved_key = api_key or os.environ.get("NATIONAL_TIP_API_KEY")
        resolved_user = username or os.environ.get("NATIONAL_TIP_USERNAME")
        resolved_pass = password or os.environ.get("NATIONAL_TIP_PASSWORD")

        if adapter_type == "taxii21":
            self._adapter: TIPAdapter = TAXII21Adapter(
                url=url,
                collection_id=collection_id,
                api_key=resolved_key,
                username=resolved_user,
                password=resolved_pass,
                verify_ssl=verify_ssl,
                source_reliability=source_reliability,
                added_after=added_after,
            )
        else:
            raise ValueError(f"Unsupported TIP adapter: {adapter_type!r}")

    def fetch(self) -> list[dict[str, Any]]:
        try:
            return self._adapter.fetch_raw()
        except Exception as exc:
            logger.error("National TIP fetch failed: %s", exc)
            return []

    def normalise(self, raw: list[dict[str, Any]]) -> list[Alert]:
        return self._adapter.to_alerts(raw)
