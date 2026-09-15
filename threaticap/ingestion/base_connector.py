"""
Abstract base connector interface.

All source connectors MUST implement this interface. The contract ensures
that the ingestion pipeline can treat every connector identically regardless
of the underlying protocol, format, or transport.
"""
from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from typing import Any, Iterator

from threaticap.models.alert import Alert

logger = logging.getLogger(__name__)


@dataclass
class ConnectorConfig:
    """Runtime configuration for a connector instance."""
    connector_id: str
    source_type: str
    source_reliability: float = 0.8
    batch_size: int = 100
    timeout_seconds: int = 30
    retry_attempts: int = 3
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class IngestResult:
    """Summary of a single ingestion run."""
    connector_id: str
    total_received: int = 0
    normalised: int = 0
    deduplicated: int = 0
    enriched: int = 0
    errors: int = 0
    error_details: list[str] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_received == 0:
            return 1.0
        return max(0.0, (self.total_received - self.errors) / self.total_received)


class BaseConnector(abc.ABC):
    """
    Abstract base class for all THREATICAP source connectors.

    Lifecycle:
        1. __init__(config) — set up connection parameters, DO NOT connect yet.
        2. connect()        — establish connection / open file handles.
        3. fetch_raw()      — yield raw payloads (generator — never load all at once).
        4. disconnect()     — clean up resources.

    The pipeline calls these methods; connectors must not call the pipeline.
    """

    def __init__(self, config: ConnectorConfig) -> None:
        self.config = config
        self._connected = False
        self._log = logging.getLogger(
            f"{__name__}.{self.__class__.__name__}.{config.connector_id}"
        )

    @property
    def connector_id(self) -> str:
        return self.config.connector_id

    @property
    def source_reliability(self) -> float:
        return self.config.source_reliability

    @abc.abstractmethod
    def connect(self) -> None:
        """Establish connection to the source system."""
        ...

    @abc.abstractmethod
    def disconnect(self) -> None:
        """Release all resources. Idempotent."""
        ...

    @abc.abstractmethod
    def fetch_raw(self) -> Iterator[dict[str, Any]]:
        """
        Yield raw payload dictionaries one at a time.

        Implementations MUST:
        - Be lazy (generator) — do not buffer the entire feed.
        - Handle transient errors internally with retry logic.
        - Raise ConnectorError on unrecoverable failure.
        """
        ...

    @abc.abstractmethod
    def normalise(self, raw: dict[str, Any]) -> Alert | None:
        """
        Map a raw payload to the canonical Alert model.

        Returns None if the payload should be silently skipped (e.g. heartbeat).
        Raises ValueError on malformed input.
        """
        ...

    def __enter__(self) -> "BaseConnector":
        self.connect()
        return self

    def __exit__(self, *_: Any) -> None:
        self.disconnect()


class ConnectorError(Exception):
    """Raised by connectors on unrecoverable failure."""
    def __init__(self, message: str, connector_id: str, cause: Exception | None = None):
        super().__init__(message)
        self.connector_id = connector_id
        self.cause = cause
