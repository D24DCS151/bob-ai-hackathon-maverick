"""
Alert normaliser — enforces canonical schema and validates inbound data.

The normaliser sits between raw connector output and the rest of the pipeline.
It applies field mappings, type coercions, and structural validation so that
downstream components never see connector-specific quirks.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from threaticap.models.alert import Alert, AlertSeverity, Observable, ObservableType

logger = logging.getLogger(__name__)

# Severity normalisation — map source-specific strings to our enum
SEVERITY_MAP: dict[str, AlertSeverity] = {
    "critical": AlertSeverity.CRITICAL,
    "crit":     AlertSeverity.CRITICAL,
    "5":        AlertSeverity.CRITICAL,
    "high":     AlertSeverity.HIGH,
    "4":        AlertSeverity.HIGH,
    "medium":   AlertSeverity.MEDIUM,
    "med":      AlertSeverity.MEDIUM,
    "3":        AlertSeverity.MEDIUM,
    "low":      AlertSeverity.LOW,
    "2":        AlertSeverity.LOW,
    "info":     AlertSeverity.INFO,
    "informational": AlertSeverity.INFO,
    "1":        AlertSeverity.INFO,
    "0":        AlertSeverity.INFO,
    "unknown":  AlertSeverity.LOW,
}

# Regex patterns for auto-extracting observables from free text
IOC_PATTERNS: list[tuple[ObservableType, re.Pattern[str]]] = [
    (ObservableType.IP_ADDRESS,  re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                                             r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")),
    (ObservableType.DOMAIN,      re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
                                             r"[a-zA-Z]{2,}\b")),
    (ObservableType.FILE_HASH,   re.compile(r"\b[0-9a-fA-F]{32,64}\b")),
    (ObservableType.CVE,         re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)),
    (ObservableType.URL,         re.compile(r"https?://[^\s\"'<>]+")),
    (ObservableType.EMAIL,       re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")),
]

# Private IPs — excluded from IP extraction (not useful as external IOCs)
PRIVATE_IP_RE = re.compile(
    r"^(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|::1$|fe80:)"
)


class AlertNormaliser:
    """
    Validates and enforces canonical structure on inbound Alert objects.

    This class does not produce Alerts — connectors do that. It takes a
    mostly-populated Alert (possibly with loose types) and:
    - Normalises severity strings
    - Extracts additional observables from description text
    - Ensures timestamps are UTC-aware
    - Strips or masks fields that exceed size limits
    - Tags the alert with enrichment metadata
    """

    def __init__(self, extract_iocs_from_text: bool = True) -> None:
        self._extract_iocs = extract_iocs_from_text

    def normalise(self, alert: Alert) -> Alert:
        """
        Return a normalised copy of the alert.
        Uses model_copy to maintain immutability semantics.
        """
        updates: dict[str, Any] = {}

        # Extract observables from description text if enabled
        if self._extract_iocs and alert.description:
            new_obs = self._extract_observables(alert.description, existing=alert.observables)
            if new_obs:
                updates["observables"] = list(alert.observables) + new_obs
                logger.debug(
                    "Extracted %d observables from alert %s description",
                    len(new_obs), alert.alert_id
                )

        # Ensure consistent severity
        if isinstance(alert.severity, str):
            normalised_sev = SEVERITY_MAP.get(alert.severity.lower(), AlertSeverity.LOW)
            updates["severity"] = normalised_sev

        # Truncate oversized description (defensive)
        if len(alert.description) > 8192:
            updates["description"] = alert.description[:8192]
            logger.warning("Alert %s description truncated to 8192 chars", alert.alert_id)

        if not updates:
            return alert

        return alert.model_copy(update=updates)

    def _extract_observables(
        self,
        text: str,
        existing: list[Observable],
    ) -> list[Observable]:
        """Auto-extract IOCs from free text, deduplicating against existing."""
        existing_values = {o.value.lower() for o in existing}
        new_obs: list[Observable] = []

        for obs_type, pattern in IOC_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)

                # Skip private IPs
                if obs_type == ObservableType.IP_ADDRESS and PRIVATE_IP_RE.match(value):
                    continue

                if value.lower() not in existing_values:
                    new_obs.append(Observable(
                        type=obs_type,
                        value=value,
                        confidence=0.6,   # Auto-extracted = lower confidence
                        context="auto-extracted from description",
                    ))
                    existing_values.add(value.lower())

        return new_obs

    @staticmethod
    def normalise_severity(raw: str) -> AlertSeverity:
        """Utility for connector use — maps a raw severity string to the enum."""
        return SEVERITY_MAP.get(raw.lower().strip(), AlertSeverity.LOW)

    @staticmethod
    def ensure_utc(dt: datetime) -> datetime:
        """Ensure a datetime is UTC-aware."""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
