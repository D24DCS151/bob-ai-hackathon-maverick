"""
Classification and coalition intelligence handling.

Implements:
1.  National classification level enforcement (UNCLASSIFIED → TOP SECRET/SCI)
2.  TLP (Traffic Light Protocol) 2.0 enforcement
3.  Compartmented handling caveats (e.g. NOFORN, RELTO, EYES ONLY)
4.  Sanitisation / redaction for outbound sharing
5.  STIX/TAXII export with selective field inclusion based on classification
6.  Sources and Methods (S&M) protection — prevents sharing of collection
    techniques or sensitive source identifiers

Design:
- ClassificationLabel is the single authority on what may be shared.
- SharingPolicy is configuration-driven and enforces outbound rules.
- IntelSanitiser produces redacted copies of alerts/threats safe for sharing.
- All decisions are audit-logged.

References:
- NATO classification markings (NATO RESTRICTED → COSMIC TOP SECRET)
- Five Eyes (FVEY) RELTO / NOFORN caveats
- STIX 2.1 data marking definitions
- TLP 2.0 (FIRST.org)
"""
from __future__ import annotations

import copy
import logging
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Classification levels
# ---------------------------------------------------------------------------

class ClassificationLevel(str, Enum):
    """
    National/NATO classification hierarchy.
    Ordered from lowest to highest sensitivity.
    """
    UNCLASSIFIED        = "UNCLASSIFIED"
    OFFICIAL            = "OFFICIAL"            # UK Official / NATO RESTRICTED equivalent
    OFFICIAL_SENSITIVE  = "OFFICIAL-SENSITIVE"
    SECRET              = "SECRET"
    TOP_SECRET          = "TOP SECRET"
    TOP_SECRET_SCI      = "TOP SECRET//SCI"     # Sensitive Compartmented Information


# Numeric ordering for comparison
_LEVEL_ORDER: dict[ClassificationLevel, int] = {
    ClassificationLevel.UNCLASSIFIED:       0,
    ClassificationLevel.OFFICIAL:           1,
    ClassificationLevel.OFFICIAL_SENSITIVE: 2,
    ClassificationLevel.SECRET:             3,
    ClassificationLevel.TOP_SECRET:         4,
    ClassificationLevel.TOP_SECRET_SCI:     5,
}


class TLPLevel(str, Enum):
    """TLP 2.0 (FIRST.org)."""
    CLEAR  = "TLP:CLEAR"
    GREEN  = "TLP:GREEN"
    AMBER  = "TLP:AMBER"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    RED    = "TLP:RED"


# TLP → maximum shareable classification level
_TLP_MAX_CLASSIFICATION: dict[TLPLevel, ClassificationLevel] = {
    TLPLevel.CLEAR:        ClassificationLevel.UNCLASSIFIED,
    TLPLevel.GREEN:        ClassificationLevel.OFFICIAL,
    TLPLevel.AMBER:        ClassificationLevel.OFFICIAL_SENSITIVE,
    TLPLevel.AMBER_STRICT: ClassificationLevel.SECRET,
    TLPLevel.RED:          ClassificationLevel.TOP_SECRET_SCI,
}


class HandlingCaveat(str, Enum):
    """Handling caveats for further access restrictions."""
    NOFORN          = "NOFORN"          # Not releasable to foreign nationals
    RELTO           = "REL TO"          # Releasable to specified nations
    EYES_ONLY       = "EYES ONLY"       # Specific eyes only
    ORCON           = "ORCON"           # Originator controlled
    NO_CONTRACT     = "NOCONTRACT"      # No contractor access
    PROPIN          = "PROPIN"          # Proprietary information
    SI              = "SI"              # Special intelligence
    SAP             = "SAP"             # Special Access Programme
    HCS             = "HCS"             # HUMINT Control System


# ---------------------------------------------------------------------------
# Sharing policy
# ---------------------------------------------------------------------------

class SharingPartner(BaseModel):
    """A trusted sharing partner — bilateral or multilateral."""
    partner_id: str
    name: str
    nations: list[str] = Field(default_factory=list, description="ISO 3166-1 alpha-3 nation codes.")
    max_classification: ClassificationLevel = ClassificationLevel.OFFICIAL
    allowed_tlp: list[TLPLevel] = Field(
        default_factory=lambda: [TLPLevel.CLEAR, TLPLevel.GREEN],
    )
    allowed_caveats: list[HandlingCaveat] = Field(default_factory=list)
    stix_feed_enabled: bool = False
    taxii_collection_id: str | None = None
    requires_sanitisation: bool = True


class SharingPolicy(BaseModel):
    """
    Organisation-wide sharing policy.

    Controls what may be shared externally, with whom, and through which channels.
    """
    organisation_id: str
    home_nation: str = Field(default="GBR", description="ISO 3166-1 alpha-3 home nation code.")
    default_classification: ClassificationLevel = ClassificationLevel.OFFICIAL_SENSITIVE
    default_tlp: TLPLevel = TLPLevel.AMBER
    sources_methods_protection: bool = Field(
        default=True,
        description="If True, source IDs, collection methods, and raw payloads are always redacted before sharing.",
    )
    redact_ip_addresses: bool = False
    redact_hostnames: bool = False
    partners: list[SharingPartner] = Field(default_factory=list)
    blocked_source_types: list[str] = Field(
        default_factory=list,
        description="Alert source types that must never be shared (e.g. HUMINT, SIGINT).",
    )

    def partner_by_id(self, partner_id: str) -> SharingPartner | None:
        return next((p for p in self.partners if p.partner_id == partner_id), None)


# ---------------------------------------------------------------------------
# Classification label
# ---------------------------------------------------------------------------

class ClassificationLabel(BaseModel):
    """
    Fully qualified classification label for a data object.

    A classification label combines level + TLP + caveats.
    The label's shareability is determined by comparing against a
    SharingPartner's allowed thresholds.
    """
    level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    tlp: TLPLevel = TLPLevel.GREEN
    caveats: list[HandlingCaveat] = Field(default_factory=list)
    releasable_to: list[str] = Field(
        default_factory=list,
        description="Nation codes this object is releasable to (when RELTO caveat applies).",
    )
    originator: str | None = None
    control_system: str | None = None  # e.g. SI, HCS, SAP name

    def is_shareable_with(self, partner: SharingPartner) -> tuple[bool, str]:
        """
        Determine whether this label permits sharing with the given partner.

        Returns (allowed: bool, reason: str).
        """
        # TLP check
        if self.tlp not in partner.allowed_tlp:
            return False, f"TLP {self.tlp.value} not in partner's allowed TLP: {[t.value for t in partner.allowed_tlp]}"

        # Classification level check
        if _LEVEL_ORDER[self.level] > _LEVEL_ORDER[partner.max_classification]:
            return False, (
                f"Classification {self.level.value} exceeds partner max "
                f"{partner.max_classification.value}"
            )

        # NOFORN check — prohibits sharing with any foreign partner
        if HandlingCaveat.NOFORN in self.caveats:
            return False, "NOFORN caveat prohibits sharing with foreign partners"

        # RELTO check
        if HandlingCaveat.RELTO in self.caveats and self.releasable_to:
            partner_nations = set(partner.nations)
            allowed_nations = set(self.releasable_to)
            if not partner_nations.intersection(allowed_nations):
                return False, f"REL TO restriction: partner nations {partner.nations} not in allowed {self.releasable_to}"

        return True, "Sharing permitted"

    @property
    def display_marking(self) -> str:
        """Full banner/header marking string."""
        parts = [self.level.value]
        if self.caveats:
            parts.append("//".join(c.value for c in self.caveats))
        if self.releasable_to:
            parts.append(f"REL TO {'/'.join(self.releasable_to)}")
        if self.control_system:
            parts.append(self.control_system)
        return "//".join(parts)


# ---------------------------------------------------------------------------
# Intel sanitiser
# ---------------------------------------------------------------------------

class IntelSanitiser:
    """
    Produces sanitised (redacted) copies of intelligence objects suitable
    for sharing with a specific partner.

    Sources and methods (S&M) protection:
    - raw_payload is always stripped
    - source_ref, source_id are anonymised to a hash
    - HUMINT / SIGINT source types are suppressed entirely
    - Network-layer observables (IPs, hostnames) optionally redacted
    """

    _PROTECTED_SOURCE_TYPES = {"HUMINT", "SIGINT"}

    def __init__(self, policy: SharingPolicy) -> None:
        self._policy = policy

    def sanitise_alert(self, alert_data: dict[str, Any], partner: SharingPartner) -> dict[str, Any] | None:
        """
        Sanitise an alert dict for the given partner.
        Returns None if the alert must not be shared at all.
        """
        sanitised = copy.deepcopy(alert_data)

        # Block protected source types
        source_type = sanitised.get("source_type", "")
        if source_type in self._PROTECTED_SOURCE_TYPES:
            if source_type in self._policy.blocked_source_types or self._policy.sources_methods_protection:
                logger.debug("Blocking %s alert from sharing (protected source type)", source_type)
                return None

        # Remove raw payload — always
        sanitised.pop("raw_payload", None)

        # Sources and methods protection
        if self._policy.sources_methods_protection:
            # Anonymise source identifiers
            if "source_ref" in sanitised:
                sanitised["source_ref"] = self._anonymise(sanitised["source_ref"])
            if "source_id" in sanitised:
                sanitised["source_id"] = f"ANON-{self._short_hash(sanitised['source_id'])}"

        # Redact IPs if policy requires
        if self._policy.redact_ip_addresses or partner.requires_sanitisation:
            ac = sanitised.get("asset_context", {})
            if isinstance(ac, dict):
                ac["ip_addresses"] = ["REDACTED" for _ in ac.get("ip_addresses", [])]

        # Redact hostnames if required
        if self._policy.redact_hostnames:
            ac = sanitised.get("asset_context", {})
            if isinstance(ac, dict) and ac.get("hostname"):
                ac["hostname"] = "REDACTED"

        # Remove enrichment_tags that may reveal collection methods
        if self._policy.sources_methods_protection:
            sanitised["enrichment_tags"] = []

        # Enforce TLP downgrade if needed
        current_tlp = sanitised.get("tlp", "TLP:GREEN")
        if not self._tlp_permitted(current_tlp, partner):
            return None  # Cannot downgrade TLP — block

        return sanitised

    def sanitise_threat(self, threat_data: dict[str, Any], partner: SharingPartner) -> dict[str, Any] | None:
        """Sanitise a CorrelatedThreat dict for sharing."""
        sanitised = copy.deepcopy(threat_data)
        # Remove audit trail — reveals internal methodology
        sanitised.pop("audit_trail", None)
        # Sanitise evidence links
        for ev in sanitised.get("evidence_links", []):
            if self._policy.sources_methods_protection:
                ev["source_ref"] = self._anonymise(ev.get("source_ref", ""))
        return sanitised

    @staticmethod
    def _anonymise(value: str) -> str:
        """Replace with an opaque identifier preserving uniqueness."""
        import hashlib
        return "ANON-" + hashlib.sha256(value.encode()).hexdigest()[:12].upper()

    @staticmethod
    def _short_hash(value: str) -> str:
        import hashlib
        return hashlib.sha256(value.encode()).hexdigest()[:8].upper()

    @staticmethod
    def _tlp_permitted(tlp_str: str, partner: SharingPartner) -> bool:
        order = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]
        max_allowed = max(
            (order.index(t.value) for t in partner.allowed_tlp if t.value in order),
            default=1
        )
        current_idx = order.index(tlp_str) if tlp_str in order else 1
        return current_idx <= max_allowed


# ---------------------------------------------------------------------------
# STIX 2.1 export helpers
# ---------------------------------------------------------------------------

class STIXExporter:
    """
    Produces STIX 2.1-compatible bundles from sanitised threat data for
    sharing via TAXII or bilateral file transfer.

    Only produces the subset of STIX objects actually needed for intel
    sharing — Indicators, Threat Actors, Attack Patterns, Relationships,
    and Sighting objects.

    For production use, replace with the official `stix2` Python library.
    This implementation produces schema-compatible plain dicts that can be
    directly passed to a stix2 Bundle constructor.
    """

    STIX_VERSION = "2.1"

    def __init__(self, policy: SharingPolicy, sanitiser: IntelSanitiser) -> None:
        self._policy = policy
        self._sanitiser = sanitiser

    def export_threat(
        self,
        threat_data: dict[str, Any],
        observables: list[dict[str, Any]],
        partner: SharingPartner,
        classification_label: ClassificationLabel,
    ) -> dict[str, Any] | None:
        """
        Build a STIX 2.1 bundle for the given threat.

        Returns None if the threat classification prevents sharing with this partner.
        """
        import uuid
        from datetime import datetime, timezone

        allowed, reason = classification_label.is_shareable_with(partner)
        if not allowed:
            logger.info(
                "STIX export blocked for partner %s: %s", partner.partner_id, reason
            )
            return None

        sanitised = self._sanitiser.sanitise_threat(threat_data, partner)
        if sanitised is None:
            return None

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        bundle_id = f"bundle--{uuid.uuid4()}"

        stix_objects: list[dict[str, Any]] = []

        # ---- Report object -----------------------------------------------
        report_obj = {
            "type": "report",
            "spec_version": self.STIX_VERSION,
            "id": f"report--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": sanitised.get("title", "Threat Intelligence Report"),
            "description": sanitised.get("description", ""),
            "published": now,
            "object_refs": [],
            "object_marking_refs": [self._tlp_marking_id(classification_label.tlp)],
            "labels": ["threat-report"],
        }

        # ---- Attack pattern objects (MITRE techniques) --------------------
        for tid in sanitised.get("mitre_technique_ids", [])[:10]:
            ap = {
                "type": "attack-pattern",
                "spec_version": self.STIX_VERSION,
                "id": f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_URL, f'mitre:{tid}')}",
                "created": now,
                "modified": now,
                "name": tid,
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": tid,
                    "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
                }],
                "object_marking_refs": [self._tlp_marking_id(classification_label.tlp)],
            }
            stix_objects.append(ap)
            report_obj["object_refs"].append(ap["id"])

        # ---- Indicator objects (observables) ----------------------------
        for obs in observables[:20]:  # Cap at 20 for bundle size
            obs_type = obs.get("type", "")
            obs_val = obs.get("value", "")
            if not obs_val or obs_val.startswith("REDACTED"):
                continue
            pattern = self._obs_to_stix_pattern(obs_type, obs_val)
            if not pattern:
                continue
            indicator = {
                "type": "indicator",
                "spec_version": self.STIX_VERSION,
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"{obs_type}: {obs_val}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "indicator_types": ["malicious-activity"],
                "object_marking_refs": [self._tlp_marking_id(classification_label.tlp)],
            }
            stix_objects.append(indicator)
            report_obj["object_refs"].append(indicator["id"])

        # ---- Threat actor (if known and shareable) ----------------------
        actor = sanitised.get("suspected_actor")
        if actor and not self._policy.sources_methods_protection:
            ta = {
                "type": "threat-actor",
                "spec_version": self.STIX_VERSION,
                "id": f"threat-actor--{uuid.uuid5(uuid.NAMESPACE_URL, f'actor:{actor}')}",
                "created": now,
                "modified": now,
                "name": actor,
                "threat_actor_types": ["nation-state"],
                "object_marking_refs": [self._tlp_marking_id(classification_label.tlp)],
            }
            stix_objects.append(ta)
            report_obj["object_refs"].append(ta["id"])

        stix_objects.append(report_obj)

        return {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": self.STIX_VERSION,
            "objects": stix_objects,
        }

    @staticmethod
    def _obs_to_stix_pattern(obs_type: str, value: str) -> str | None:
        mapping = {
            "ipv4-addr":    f"[ipv4-addr:value = '{value}']",
            "ipv6-addr":    f"[ipv6-addr:value = '{value}']",
            "domain-name":  f"[domain-name:value = '{value}']",
            "url":          f"[url:value = '{value}']",
            "file:hashes":  f"[file:hashes.'SHA-256' = '{value}']",
            "email-addr":   f"[email-message:sender_ref.value = '{value}']",
        }
        return mapping.get(obs_type)

    @staticmethod
    def _tlp_marking_id(tlp: TLPLevel) -> str:
        """Standard STIX 2.1 TLP marking definition IDs (FIRST.org)."""
        ids = {
            TLPLevel.CLEAR:        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            TLPLevel.GREEN:        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            TLPLevel.AMBER:        "marking-definition--f88d31f6-1f26-4a72-a073-be5a1b2c5b2f",
            TLPLevel.AMBER_STRICT: "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
            TLPLevel.RED:          "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        }
        return ids.get(tlp, ids[TLPLevel.AMBER])
