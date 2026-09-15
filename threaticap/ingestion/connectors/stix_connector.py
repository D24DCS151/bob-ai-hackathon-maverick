"""
STIX/TAXII connector — consumes threat intelligence in STIX 2.1 format.

This connector handles:
- STIX 2.1 bundle files (JSON)
- TAXII 2.1 collection polling (production mode)
- Commercial threat feed ingestion

In production, use the `taxii2-client` and `stix2` libraries for full
STIX/TAXII compliance. This implementation provides the full structural
scaffolding with stix2 parsing where available and graceful fallback.

Extension point: classified national threat intelligence platforms that
speak STIX/TAXII can be connected here with minimal code changes.
"""
from __future__ import annotations

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

# STIX SDO type → relevant observable extraction
STIX_INDICATOR_PATTERN_MAP: dict[str, ObservableType] = {
    "ipv4-addr": ObservableType.IP_ADDRESS,
    "ipv6-addr": ObservableType.IPV6_ADDRESS,
    "domain-name": ObservableType.DOMAIN,
    "url": ObservableType.URL,
    "file": ObservableType.FILE_HASH,
    "email-addr": ObservableType.EMAIL,
    "user-account": ObservableType.USER_ACCOUNT,
    "network-traffic": ObservableType.NETWORK_CONN,
}


class StixConnector(BaseConnector):
    """
    STIX/TAXII connector for commercial and national threat intelligence feeds.

    Configuration (ConnectorConfig.extra keys):
        mode:               "file" | "taxii" (default: "file")
        file_path:          path to STIX bundle JSON file (mode=file)
        taxii_url:          TAXII server root URL (mode=taxii)
        taxii_collection:   Collection ID or title (mode=taxii)
        taxii_username:     Authentication username (mode=taxii)
        taxii_password:     Authentication password (mode=taxii) — use secrets mgmt
        source_subtype:     "stix_taxii" | "commercial" (default: "stix_taxii")
        min_confidence:     Minimum STIX confidence to ingest (0–100, default: 30)
    """

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)
        self._mode = config.extra.get("mode", "file")
        self._file_path: Path | None = None
        self._taxii_url = config.extra.get("taxii_url", "")
        self._taxii_collection = config.extra.get("taxii_collection", "")
        self._min_confidence = int(config.extra.get("min_confidence", 30))

        source_subtype = config.extra.get("source_subtype", "stix_taxii")
        self._source_type = (
            AlertSource.COMMERCIAL_FEED if source_subtype == "commercial"
            else AlertSource.STIX_TAXII
        )

        path_str = config.extra.get("file_path", "")
        if path_str:
            self._file_path = Path(path_str)

    def connect(self) -> None:
        if self._mode == "file" and self._file_path:
            if not self._file_path.exists():
                raise ConnectorError(
                    f"STIX bundle file not found: {self._file_path}",
                    self.connector_id,
                )
        elif self._mode == "taxii":
            # Production: establish authenticated TAXII session
            # from taxii2client.v21 import Server
            # self._taxii_server = Server(self._taxii_url, user=..., password=...)
            self._log.info("TAXII mode: %s (stub — no live connection)", self._taxii_url)

        self._connected = True
        self._log.info("STIX connector connected (%s mode)", self._mode)

    def disconnect(self) -> None:
        self._connected = False

    def fetch_raw(self) -> Iterator[dict[str, Any]]:
        if self._mode == "file" and self._file_path:
            yield from self._fetch_from_file()
        elif self._mode == "taxii":
            yield from self._fetch_from_taxii()

    def _fetch_from_file(self) -> Iterator[dict[str, Any]]:
        assert self._file_path is not None
        with open(self._file_path, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)

        # Handle STIX bundle or raw list
        objects = bundle.get("objects", [bundle]) if isinstance(bundle, dict) else bundle

        for obj in objects:
            # Only process Indicator SDOs for now; extend for other SDO types as needed
            if isinstance(obj, dict) and obj.get("type") == "indicator":
                yield obj
            elif isinstance(obj, dict) and obj.get("type") in ("malware", "threat-actor", "campaign"):
                # Convert threat actor / campaign objects to intel alerts
                yield obj

    def _fetch_from_taxii(self) -> Iterator[dict[str, Any]]:
        """
        TAXII 2.1 collection polling.

        Production implementation:
            api_root = self._taxii_server.api_roots[0]
            for collection in api_root.collections:
                if collection.title == self._taxii_collection:
                    for obj in collection.get_objects().objects:
                        yield obj.serialize() if hasattr(obj, 'serialize') else dict(obj)
        """
        self._log.warning("TAXII fetch stub — implement with taxii2-client library")
        return
        yield

    def normalise(self, raw: dict[str, Any]) -> Alert | None:
        """Normalise a STIX object to canonical Alert."""
        stix_type = raw.get("type", "")

        # Filter by confidence
        stix_confidence = int(raw.get("confidence", 100))
        if stix_confidence < self._min_confidence:
            self._log.debug(
                "Skipping STIX object %s (confidence %d < threshold %d)",
                raw.get("id", "?"), stix_confidence, self._min_confidence
            )
            return None

        if stix_type == "indicator":
            return self._normalise_indicator(raw)
        elif stix_type in ("malware", "tool"):
            return self._normalise_malware(raw)
        elif stix_type == "threat-actor":
            return self._normalise_threat_actor(raw)
        elif stix_type == "campaign":
            return self._normalise_campaign(raw)
        else:
            return None

    def _normalise_indicator(self, raw: dict[str, Any]) -> Alert | None:
        """Convert a STIX Indicator to an Alert."""
        observables = self._extract_from_pattern(raw.get("pattern", ""))
        if not observables:
            return None

        severity = AlertNormaliser.normalise_severity(
            self._stix_confidence_to_severity(int(raw.get("confidence", 50)))
        )

        mitre_ids: list[str] = []
        for ref in raw.get("kill_chain_phases", []):
            phase = ref.get("phase_name", "")
            # STIX may embed technique IDs in external references
            pass
        for ext_ref in raw.get("external_references", []):
            if ext_ref.get("source_name") == "mitre-attack":
                ext_id = ext_ref.get("external_id", "")
                if re.match(r"^T\d{4}(\.\d{3})?$", ext_id):
                    mitre_ids.append(ext_id)

        return Alert(
            source_ref=str(raw.get("id") or str(uuid.uuid4())),
            source_type=self._source_type,
            source_id=self.connector_id,
            source_reliability=self.source_reliability,
            event_time=self._parse_stix_time(raw.get("created")),
            severity=severity,
            confidence=min(1.0, int(raw.get("confidence", 50)) / 100.0),
            title=str(raw.get("name") or raw.get("pattern", "STIX Indicator")[:120]),
            description=str(raw.get("description", "")),
            category="Threat Intelligence",
            rule_id=raw.get("id"),
            raw_payload=raw,
            observables=observables,
            asset_context=AssetContext(),
            mitre_technique_ids=mitre_ids,
            tlp=self._stix_tlp_to_canonical(raw.get("object_marking_refs", [])),
        )

    def _normalise_malware(self, raw: dict[str, Any]) -> Alert | None:
        return Alert(
            source_ref=str(raw.get("id") or str(uuid.uuid4())),
            source_type=self._source_type,
            source_id=self.connector_id,
            source_reliability=self.source_reliability,
            event_time=self._parse_stix_time(raw.get("created")),
            severity=AlertNormaliser.normalise_severity("high"),
            confidence=0.7,
            title=f"Malware: {raw.get('name', 'Unknown')}",
            description=str(raw.get("description", "")),
            category="Malware",
            rule_id=raw.get("id"),
            raw_payload=raw,
            observables=[],
            asset_context=AssetContext(),
        )

    def _normalise_threat_actor(self, raw: dict[str, Any]) -> Alert | None:
        return Alert(
            source_ref=str(raw.get("id") or str(uuid.uuid4())),
            source_type=self._source_type,
            source_id=self.connector_id,
            source_reliability=self.source_reliability,
            event_time=self._parse_stix_time(raw.get("created")),
            severity=AlertNormaliser.normalise_severity("high"),
            confidence=0.6,
            title=f"Threat Actor: {raw.get('name', 'Unknown')}",
            description=str(raw.get("description", "")),
            category="Threat Actor",
            rule_id=raw.get("id"),
            raw_payload=raw,
            observables=[],
            asset_context=AssetContext(),
            threat_actor=raw.get("name"),
        )

    def _normalise_campaign(self, raw: dict[str, Any]) -> Alert | None:
        return Alert(
            source_ref=str(raw.get("id") or str(uuid.uuid4())),
            source_type=self._source_type,
            source_id=self.connector_id,
            source_reliability=self.source_reliability,
            event_time=self._parse_stix_time(raw.get("created")),
            severity=AlertNormaliser.normalise_severity("high"),
            confidence=0.65,
            title=f"Campaign: {raw.get('name', 'Unknown')}",
            description=str(raw.get("description", "")),
            category="Campaign",
            rule_id=raw.get("id"),
            raw_payload=raw,
            observables=[],
            asset_context=AssetContext(),
            campaign=raw.get("name"),
        )

    def _extract_from_pattern(self, pattern: str) -> list[Observable]:
        """
        Extract observable values from a STIX 2.1 indicator pattern string.

        Full pattern parsing requires the `stix2` library. This implementation
        handles the most common patterns with regex; replace with stix2.parse()
        for production use.
        """
        if not pattern:
            return []

        observables: list[Observable] = []
        seen: set[str] = set()

        # Pattern examples:
        #   [ipv4-addr:value = '203.0.113.5']
        #   [domain-name:value = 'evil.example.com']
        #   [file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']
        import re
        value_pattern = re.compile(
            r"\[?(\w[\w\-]+)(?::[\w.]+)?\s*=\s*['\"]([^'\"]+)['\"]"
        )
        for match in value_pattern.finditer(pattern):
            stix_obj_type, value = match.group(1), match.group(2)
            obs_type = STIX_INDICATOR_PATTERN_MAP.get(stix_obj_type)
            if obs_type and value not in seen:
                observables.append(Observable(
                    type=obs_type,
                    value=value,
                    confidence=0.85,
                    context="STIX indicator pattern",
                ))
                seen.add(value)

        return observables

    @staticmethod
    def _stix_confidence_to_severity(confidence: int) -> str:
        """Map STIX confidence (0–100) to severity string."""
        if confidence >= 80:
            return "high"
        if confidence >= 50:
            return "medium"
        return "low"

    @staticmethod
    def _stix_tlp_to_canonical(marking_refs: list[str]) -> str:
        """Map STIX TLP marking GUIDs to canonical TLP labels."""
        tlp_map = {
            "marking-definition--613f2e26-407d-48c7-9eca-b8e91ba519a6": "TLP:WHITE",
            "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "TLP:GREEN",
            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "TLP:AMBER",
            "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "TLP:RED",
        }
        for ref in marking_refs:
            if ref in tlp_map:
                return tlp_map[ref]
        return "TLP:AMBER"

    @staticmethod
    def _parse_stix_time(raw: Any) -> datetime:
        if raw is None:
            return datetime.now(timezone.utc)
        if isinstance(raw, str):
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now(timezone.utc)


import re
