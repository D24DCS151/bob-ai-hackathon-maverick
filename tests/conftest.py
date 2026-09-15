"""Shared test fixtures."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from threaticap.models.alert import Alert, AlertSeverity, AlertSource, AssetContext, Observable, ObservableType


def make_alert(
    alert_id: str = "alert-001",
    source_ref: str = "SRC-001",
    source_type: AlertSource = AlertSource.SIEM,
    source_id: str = "siem-01",
    severity: AlertSeverity = AlertSeverity.HIGH,
    title: str = "Test Alert",
    description: str = "Test alert description",
    event_time: datetime | None = None,
    observables: list[Observable] | None = None,
    mitre_technique_ids: list[str] | None = None,
    asset_context: AssetContext | None = None,
    source_reliability: float = 0.8,
    confidence: float = 0.75,
    threat_actor: str | None = None,
    campaign: str | None = None,
) -> Alert:
    if event_time is None:
        event_time = datetime.now(timezone.utc)
    return Alert(
        alert_id=alert_id,
        source_ref=source_ref,
        source_type=source_type,
        source_id=source_id,
        event_time=event_time,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        observables=observables or [],
        mitre_technique_ids=mitre_technique_ids or [],
        asset_context=asset_context or AssetContext(),
        source_reliability=source_reliability,
        threat_actor=threat_actor,
        campaign=campaign,
    )


def make_observable(
    obs_type: ObservableType = ObservableType.IP_ADDRESS,
    value: str = "203.0.113.1",
    confidence: float = 0.9,
) -> Observable:
    return Observable(type=obs_type, value=value, confidence=confidence)


@pytest.fixture
def base_alert():
    return make_alert()


@pytest.fixture
def critical_alert():
    return make_alert(
        alert_id="alert-critical",
        severity=AlertSeverity.CRITICAL,
        confidence=0.95,
        observables=[
            make_observable(ObservableType.FILE_HASH, "deadbeef" * 8),
            make_observable(ObservableType.IP_ADDRESS, "203.0.113.45"),
        ],
        mitre_technique_ids=["T1059.001", "T1003"],
        asset_context=AssetContext(criticality=0.9, hostname="dc01.corp.internal"),
    )


@pytest.fixture
def alert_pair_with_shared_ioc():
    """Two alerts sharing an IP observable — should correlate."""
    obs = make_observable(ObservableType.IP_ADDRESS, "203.0.113.45")
    a = make_alert(
        alert_id="alert-A",
        source_type=AlertSource.SIEM,
        observables=[obs],
    )
    b = make_alert(
        alert_id="alert-B",
        source_type=AlertSource.EDR,
        observables=[obs, make_observable(ObservableType.FILE_HASH, "aabbccdd" * 8)],
    )
    return a, b


@pytest.fixture
def false_positive_alert():
    """Low-severity, single-source alert — likely false positive."""
    return make_alert(
        alert_id="alert-fp",
        severity=AlertSeverity.INFO,
        source_type=AlertSource.SIEM,
        source_id="siem-01",
        confidence=0.3,
        source_reliability=0.4,
    )
