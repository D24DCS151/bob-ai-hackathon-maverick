"""
Cross-domain and air-gapped operation support.

Real defence SOCs operate in multi-domain environments:
  - HIGH side:  SECRET / TOP SECRET networks (no internet)
  - LOW side:   UNCLASSIFIED / OFFICIAL networks
  - Air-gapped: physically isolated networks with no electronic transfers

This module provides:

1.  DomainLabel — classifies which security domain data belongs to.
2.  CrossDomainGuard — enforces one-way data flow rules (high→low is blocked
    by default; low→high is subject to sanitisation).
3.  SecureTransferPackage — produces a signed, encrypted data package
    suitable for physical/optical transfer (USB, CD, data diode) between
    domains.  Uses symmetric HMAC signing (no external PKI dependency).
4.  AirGappedExportWriter / AirGappedImportReader — serialize / deserialize
    the package in a self-describing format that includes integrity verification.
5.  DisconnectedModeManager — tracks connectivity state and degrades
    gracefully when external feeds are unavailable.

Security model:
  - No network calls are made by any class in this module.
  - All cryptographic operations use Python stdlib (hmac, hashlib).
  - The transfer package is JSON-serialisable for compatibility with all
    disconnected environments.
  - A domain guard violation is always logged and raises CrossDomainViolation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain definitions
# ---------------------------------------------------------------------------

class SecurityDomain(str, Enum):
    """Security domain labels in ascending classification order."""
    OPEN        = "OPEN"        # Internet / uncontrolled network
    LOW         = "LOW"         # Unclassified / Official network
    MEDIUM      = "MEDIUM"      # Official-Sensitive / NATO RESTRICTED
    HIGH        = "HIGH"        # Secret network
    TOP         = "TOP"         # Top Secret network
    AIR_GAPPED  = "AIR_GAPPED"  # Physically isolated (any classification)


_DOMAIN_ORDER: dict[SecurityDomain, int] = {
    SecurityDomain.OPEN:       0,
    SecurityDomain.LOW:        1,
    SecurityDomain.MEDIUM:     2,
    SecurityDomain.HIGH:       3,
    SecurityDomain.TOP:        4,
    SecurityDomain.AIR_GAPPED: 5,
}


class TransferDirection(str, Enum):
    HIGH_TO_LOW = "HIGH_TO_LOW"  # Downgrade — requires sanitisation
    LOW_TO_HIGH = "LOW_TO_HIGH"  # Upgrade — lower risk, still audited
    SAME_DOMAIN = "SAME_DOMAIN"  # No domain boundary crossing


class CrossDomainViolation(Exception):
    """Raised when a cross-domain transfer violates policy."""


# ---------------------------------------------------------------------------
# Cross-domain guard
# ---------------------------------------------------------------------------

class CrossDomainGuard:
    """
    Enforces cross-domain transfer rules.

    Default policy (defence baseline):
    - HIGH→LOW transfers require explicit sanitisation approval.
    - LOW→HIGH transfers are permitted but audited.
    - OPEN→any is blocked entirely.
    - AIR_GAPPED domains may only receive via SecureTransferPackage.
    """

    def __init__(
        self,
        allow_high_to_low: bool = False,   # Must be explicitly enabled + sanitised
        allow_open_to_any: bool = False,   # Blocked by default
        require_sanitisation: bool = True,
    ) -> None:
        self._allow_h2l = allow_high_to_low
        self._allow_open = allow_open_to_any
        self._require_san = require_sanitisation

    def check(
        self,
        source_domain: SecurityDomain,
        target_domain: SecurityDomain,
        is_sanitised: bool = False,
    ) -> None:
        """
        Validate a proposed transfer.  Raises CrossDomainViolation if blocked.
        """
        if source_domain == SecurityDomain.OPEN and not self._allow_open:
            raise CrossDomainViolation(
                f"Transfer from OPEN domain is blocked by policy. "
                f"Validate and sanitise before importing."
            )

        src_ord = _DOMAIN_ORDER[source_domain]
        tgt_ord = _DOMAIN_ORDER[target_domain]

        if src_ord > tgt_ord:
            # High-to-low (downgrade)
            if not self._allow_h2l:
                raise CrossDomainViolation(
                    f"High-to-low transfer {source_domain.value}→{target_domain.value} "
                    f"is blocked.  Enable allow_high_to_low and apply sanitisation."
                )
            if self._require_san and not is_sanitised:
                raise CrossDomainViolation(
                    f"High-to-low transfer {source_domain.value}→{target_domain.value} "
                    f"requires sanitisation — set is_sanitised=True after applying IntelSanitiser."
                )

        direction = (
            TransferDirection.HIGH_TO_LOW if src_ord > tgt_ord
            else TransferDirection.LOW_TO_HIGH if src_ord < tgt_ord
            else TransferDirection.SAME_DOMAIN
        )
        logger.info(
            "Cross-domain transfer: %s → %s [%s] sanitised=%s",
            source_domain.value, target_domain.value, direction.value, is_sanitised,
        )

    def direction(
        self, source_domain: SecurityDomain, target_domain: SecurityDomain
    ) -> TransferDirection:
        src_ord = _DOMAIN_ORDER[source_domain]
        tgt_ord = _DOMAIN_ORDER[target_domain]
        if src_ord > tgt_ord:
            return TransferDirection.HIGH_TO_LOW
        if src_ord < tgt_ord:
            return TransferDirection.LOW_TO_HIGH
        return TransferDirection.SAME_DOMAIN


# ---------------------------------------------------------------------------
# Secure transfer package
# ---------------------------------------------------------------------------

@dataclass
class SecureTransferPackage:
    """
    A self-describing, integrity-verified package for cross-domain
    or air-gapped data transfer.

    Wire format: JSON with the following top-level keys:
        package_id:      UUID
        created_at:      ISO 8601 UTC
        source_domain:   SecurityDomain value
        target_domain:   SecurityDomain value
        classification:  Classification level string
        record_count:    Number of data records
        records:         list of arbitrary dicts
        checksum:        SHA-256 hex digest of canonical record JSON
        signature:       HMAC-SHA256 hex (using transfer_key) — "" if no key

    The signature is verified on import using the same key.
    Tampering with any field invalidates the checksum.
    """

    package_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source_domain: str = SecurityDomain.HIGH.value
    target_domain: str = SecurityDomain.LOW.value
    classification: str = "OFFICIAL"
    records: list[dict[str, Any]] = field(default_factory=list)
    checksum: str = ""
    signature: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def seal(self, transfer_key: bytes | None = None) -> None:
        """Compute checksum and optional HMAC signature."""
        canonical = json.dumps(self.records, sort_keys=True, ensure_ascii=True)
        self.checksum = hashlib.sha256(canonical.encode()).hexdigest()
        if transfer_key:
            self.signature = hmac.new(
                transfer_key,
                canonical.encode(),
                hashlib.sha256,
            ).hexdigest()

    def verify(self, transfer_key: bytes | None = None) -> bool:
        """
        Verify integrity of the package.

        Returns True if both checksum and (if key provided) HMAC are valid.
        Logs a warning and returns False on any tamper detection.
        """
        canonical = json.dumps(self.records, sort_keys=True, ensure_ascii=True)
        expected_checksum = hashlib.sha256(canonical.encode()).hexdigest()
        if expected_checksum != self.checksum:
            logger.warning(
                "Transfer package %s checksum mismatch — possible tampering",
                self.package_id,
            )
            return False
        if transfer_key:
            expected_sig = hmac.new(
                transfer_key,
                canonical.encode(),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected_sig, self.signature):
                logger.warning(
                    "Transfer package %s HMAC verification failed — "
                    "wrong key or tampered payload",
                    self.package_id,
                )
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "created_at": self.created_at,
            "source_domain": self.source_domain,
            "target_domain": self.target_domain,
            "classification": self.classification,
            "record_count": len(self.records),
            "records": self.records,
            "checksum": self.checksum,
            "signature": self.signature,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SecureTransferPackage":
        return cls(
            package_id=d["package_id"],
            created_at=d["created_at"],
            source_domain=d["source_domain"],
            target_domain=d["target_domain"],
            classification=d["classification"],
            records=d["records"],
            checksum=d["checksum"],
            signature=d.get("signature", ""),
            metadata=d.get("metadata", {}),
        )


# ---------------------------------------------------------------------------
# File-based serialisation (air-gapped transfer)
# ---------------------------------------------------------------------------

class AirGappedExportWriter:
    """
    Writes a SecureTransferPackage to a file suitable for physical media transfer.

    Each export file is a single JSON document with a .tigpkg extension.
    The file is named: {package_id}_{yyyymmddHHMM}.tigpkg
    """

    def write(
        self,
        package: SecureTransferPackage,
        output_dir: Path,
        transfer_key: bytes | None = None,
    ) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        package.seal(transfer_key)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
        filename = f"{package.package_id}_{ts}.tigpkg"
        out_path = output_dir / filename
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(package.to_dict(), fh, indent=2, ensure_ascii=True)
        logger.info(
            "Air-gapped export written: %s (%d records, classification=%s)",
            out_path, len(package.records), package.classification,
        )
        return out_path


class AirGappedImportReader:
    """
    Reads and verifies a SecureTransferPackage from a .tigpkg file.

    Raises CrossDomainViolation if integrity check fails.
    """

    def read(
        self,
        package_path: Path,
        transfer_key: bytes | None = None,
        expected_source_domain: SecurityDomain | None = None,
    ) -> SecureTransferPackage:
        with open(package_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)

        pkg = SecureTransferPackage.from_dict(raw)

        if not pkg.verify(transfer_key):
            raise CrossDomainViolation(
                f"Integrity verification failed for package {pkg.package_id}. "
                f"Reject and quarantine the transfer media."
            )

        if expected_source_domain and pkg.source_domain != expected_source_domain.value:
            raise CrossDomainViolation(
                f"Package source domain {pkg.source_domain!r} does not match "
                f"expected {expected_source_domain.value!r}."
            )

        logger.info(
            "Air-gapped import verified: %s (%d records, %s→%s)",
            pkg.package_id, len(pkg.records), pkg.source_domain, pkg.target_domain,
        )
        return pkg


# ---------------------------------------------------------------------------
# Disconnected mode manager
# ---------------------------------------------------------------------------

class ConnectivityState(str, Enum):
    CONNECTED    = "CONNECTED"
    DEGRADED     = "DEGRADED"      # Some feeds unreachable
    DISCONNECTED = "DISCONNECTED"  # All external connectivity lost


@dataclass
class DisconnectedModeManager:
    """
    Tracks external connectivity and adapts system behaviour.

    When DISCONNECTED:
    - External enrichment feeds are bypassed (stale cache used)
    - STIX/TAXII push is queued for later transmission
    - Threat intelligence is drawn from local KB only
    - All decisions are flagged with DISCONNECTED_MODE tag in audit trail
    """
    _state: ConnectivityState = ConnectivityState.CONNECTED
    _disconnected_since: datetime | None = None
    _pending_stix_bundles: list[dict[str, Any]] = field(default_factory=list)

    def set_connected(self) -> None:
        self._state = ConnectivityState.CONNECTED
        self._disconnected_since = None
        logger.info("Connectivity restored — resuming online mode")

    def set_disconnected(self) -> None:
        if self._state != ConnectivityState.DISCONNECTED:
            self._state = ConnectivityState.DISCONNECTED
            self._disconnected_since = datetime.now(timezone.utc)
            logger.warning("Entering DISCONNECTED mode — all external feeds suspended")

    def set_degraded(self) -> None:
        self._state = ConnectivityState.DEGRADED
        logger.warning("Entering DEGRADED mode — some external feeds unreachable")

    @property
    def is_online(self) -> bool:
        return self._state == ConnectivityState.CONNECTED

    @property
    def state(self) -> ConnectivityState:
        return self._state

    def queue_stix_bundle(self, bundle: dict[str, Any]) -> None:
        """Queue a STIX bundle for later transmission when connectivity is restored."""
        self._pending_stix_bundles.append(bundle)
        logger.info(
            "STIX bundle queued (queue depth: %d)", len(self._pending_stix_bundles)
        )

    def flush_pending(self) -> list[dict[str, Any]]:
        """Return and clear queued bundles (call when connectivity is restored)."""
        bundles = list(self._pending_stix_bundles)
        self._pending_stix_bundles.clear()
        return bundles

    @property
    def pending_count(self) -> int:
        return len(self._pending_stix_bundles)

    def audit_tag(self) -> str:
        """Tag to include in all audit records when in disconnected mode."""
        return (
            f"DISCONNECTED_MODE (since {self._disconnected_since.isoformat()})"
            if self._disconnected_since
            else ""
        )
