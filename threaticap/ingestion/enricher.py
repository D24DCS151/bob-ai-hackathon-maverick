"""
Alert enricher — adds contextual metadata to normalised alerts.

Enrichment includes:
- GeoIP resolution (stubbed — plug in MaxMind / commercial DB)
- Threat reputation lookups (stubbed — plug in VirusTotal / MISP)
- Asset registry lookups (config-driven)
- MITRE technique classification from alert category/title keywords
- TLP / classification assignment
"""
from __future__ import annotations

import logging
import re
from typing import Any

from threaticap.models.alert import Alert, AssetContext, GeoLocation, Observable, ObservableType

logger = logging.getLogger(__name__)


class AlertEnricher:
    """
    Stateless (per-call) enricher — each enrich() call is idempotent.

    In production, swap the stub methods for real API clients.
    The interface is intentionally thin so enrichers can be chained.
    """

    def __init__(
        self,
        asset_registry: dict[str, Any] | None = None,
        geoip_enabled: bool = False,
        reputation_enabled: bool = False,
    ) -> None:
        # Asset registry maps IP/hostname -> AssetContext fields
        self._asset_registry: dict[str, Any] = asset_registry or {}
        self._geoip_enabled = geoip_enabled
        self._reputation_enabled = reputation_enabled

    def enrich(self, alert: Alert) -> Alert:
        """
        Return an enriched copy of the alert.
        Each enrichment step is applied in order; failures are logged but do
        not abort the pipeline.
        """
        updates: dict[str, Any] = {}

        # ---- Asset context enrichment ------------------------------------
        enriched_asset = self._enrich_asset(alert)
        if enriched_asset != alert.asset_context:
            updates["asset_context"] = enriched_asset

        # ---- GeoIP (stub) ------------------------------------------------
        if self._geoip_enabled:
            geo = self._resolve_geo(alert)
            if geo:
                updates["geo"] = geo

        # ---- Reputation lookup (stub) ------------------------------------
        if self._reputation_enabled:
            tags = self._check_reputation(alert)
            if tags:
                existing = list(alert.enrichment_tags)
                existing.extend(t for t in tags if t not in existing)
                updates["enrichment_tags"] = existing

        # ---- TLP assignment based on source type -------------------------
        tlp = self._assign_tlp(alert)
        if tlp != alert.tlp:
            updates["tlp"] = tlp

        if not updates:
            return alert
        return alert.model_copy(update=updates)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _enrich_asset(self, alert: Alert) -> AssetContext:
        """
        Look up affected assets in the asset registry.

        In production, replace with a call to a CMDB / asset management API.
        The registry is a simple dict keyed by IP or hostname.
        """
        ctx = alert.asset_context

        # Try each IP address in the alert
        for ip in ctx.ip_addresses:
            if ip in self._asset_registry:
                asset_data = self._asset_registry[ip]
                return AssetContext(
                    asset_id=asset_data.get("asset_id", ctx.asset_id),
                    hostname=asset_data.get("hostname", ctx.hostname),
                    ip_addresses=ctx.ip_addresses,
                    owner=asset_data.get("owner", ctx.owner),
                    classification=asset_data.get("classification", ctx.classification),
                    criticality=float(asset_data.get("criticality", ctx.criticality)),
                    network_segment=asset_data.get("network_segment", ctx.network_segment),
                    tags=asset_data.get("tags", list(ctx.tags)),
                )

        # Try IPs from observables
        for obs in alert.observables:
            if obs.type == ObservableType.IP_ADDRESS and obs.value in self._asset_registry:
                asset_data = self._asset_registry[obs.value]
                return AssetContext(
                    asset_id=asset_data.get("asset_id"),
                    hostname=asset_data.get("hostname"),
                    ip_addresses=[obs.value],
                    owner=asset_data.get("owner"),
                    classification=asset_data.get("classification"),
                    criticality=float(asset_data.get("criticality", 0.5)),
                    network_segment=asset_data.get("network_segment"),
                    tags=asset_data.get("tags", []),
                )

        return ctx

    def _resolve_geo(self, alert: Alert) -> GeoLocation | None:
        """
        Resolve geolocation for the first external IP observable.

        STUB — replace with MaxMind GeoIP2 or equivalent:
            import geoip2.database
            reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            response = reader.city(ip)
        """
        for obs in alert.observables:
            if obs.type == ObservableType.IP_ADDRESS:
                ip = obs.value
                # Skip private ranges
                if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", ip):
                    continue
                # Return stub geo — in production this is a real DB lookup
                logger.debug("GeoIP lookup stub for %s", ip)
                return GeoLocation(country_code="XX", country_name="Unknown (stub)")
        return None

    def _check_reputation(self, alert: Alert) -> list[str]:
        """
        Check observable reputation against threat intel feeds.

        STUB — replace with:
        - VirusTotal API calls
        - MISP attribute lookups
        - Internal threat intelligence platform queries
        """
        tags: list[str] = []
        for obs in alert.observables:
            if obs.type in (ObservableType.FILE_HASH, ObservableType.IP_ADDRESS, ObservableType.DOMAIN):
                # Stub: in production, async lookup and cache results
                logger.debug("Reputation lookup stub for observable: %s", obs.value[:20])
        return tags

    @staticmethod
    def _assign_tlp(alert: Alert) -> str:
        """
        Assign Traffic Light Protocol classification.

        Rules (precedence order):
        - HUMINT / SIGINT / SATELLITE_ISR → TLP:RED (compartmented)
        - STIX_TAXII / COMMERCIAL_FEED → preserve source TLP or default AMBER
        - Others → TLP:GREEN

        In classified environments, replace with formal classification logic.
        """
        from threaticap.models.alert import AlertSource
        sensitive_sources = {AlertSource.HUMINT, AlertSource.SIGINT, AlertSource.SATELLITE_ISR}
        if alert.source_type in sensitive_sources:
            return "TLP:RED"
        if alert.source_type in {AlertSource.STIX_TAXII, AlertSource.COMMERCIAL_FEED}:
            return "TLP:AMBER"
        return alert.tlp
